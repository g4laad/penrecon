"""Scan imports/comparisons, search/export, and operator notes/triage."""
from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlmodel import Session, col, select

from penrecon import queries
from penrecon.db import get_session
from penrecon.ingest import ScanParseError, ingest_scan
from penrecon.models import Host, Note, Scan, Status
from penrecon.parsers import PARSERS
from penrecon.web.common import MAX_UPLOAD_BYTES, MutationResponse, mutation_response, require_engagement
from penrecon.web.inventory_schemas import AnnotationResponse, HostRowResponse
from penrecon.web.serialization import encode_page

router = APIRouter(tags=["Evidence"])


class ScanResponse(BaseModel):
    id: int
    filename: str
    tool: str
    imported_at: datetime
    host_count: int


class ScansResponse(BaseModel):
    scans: list[ScanResponse]
    tools: list[str]


class ScanReference(BaseModel):
    id: int
    filename: str


class DiffEntryResponse(BaseModel):
    ip: str
    port: int
    proto: str
    kind: str
    before: str | None
    after: str | None


class DiffResultResponse(BaseModel):
    scan_a: ScanReference
    scan_b: ScanReference
    entries: list[DiffEntryResponse]


class DiffResponse(BaseModel):
    scans: list[ScanResponse]
    result: DiffResultResponse | None
    a: int | None
    b: int | None


class NoteHitResponse(BaseModel):
    href: str
    where: str
    title: str
    preview: str


class SearchHostLink(BaseModel):
    host_id: int
    ip: str


class CredentialHitResponse(BaseModel):
    id: int
    kind: str
    username: str
    hosts: list[SearchHostLink]


class SearchResultsResponse(BaseModel):
    hosts: list[HostRowResponse]
    notes: list[NoteHitResponse]
    credentials: list[CredentialHitResponse]


class SearchResponse(BaseModel):
    q: str
    results: SearchResultsResponse


class AnnotationContextResponse(BaseModel):
    host_id: int
    ann: AnnotationResponse | None
    statuses: list[Status]
    saved: bool


def owned_host(session: Session, host_id: int, engagement_id: str) -> Host:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        raise HTTPException(404, detail="host not found")
    return host


@router.get("/search", response_model=SearchResponse)
def search(q: str = "", engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> JSONResponse:
    return JSONResponse(encode_page({"q": q.strip(), "results": queries.search(session, q, engagement_id=engagement_id)}))


@router.get("/export/hosts.csv", response_class=Response, responses={200: {"content": {"text/csv": {"schema": {"type": "string", "format": "binary"}}}, "description": "Current inventory, one row per service; spreadsheet formulas escaped."}})
def export_hosts_csv(engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=queries.EXPORT_COLUMNS)
    writer.writeheader()
    writer.writerows(queries.export_rows(session, engagement_id=engagement_id))
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="penrecon-hosts-{stamp}.csv"'})


@router.get("/scans", response_model=ScansResponse)
def scans(engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> JSONResponse:
    rows = session.exec(select(Scan).where(Scan.engagement_id == engagement_id).order_by(col(Scan.imported_at).desc())).all()
    return JSONResponse(encode_page({"scans": rows, "tools": sorted(PARSERS)}))


@router.post("/scans", response_model=MutationResponse, response_model_exclude_unset=True)
async def upload_scan(request: Request, file: UploadFile, tool: str = Form("nmap"), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> JSONResponse:
    try:
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail="Scan exceeds the 32 MiB upload limit.")
        try:
            ingest_scan(session, data, file.filename or "upload", tool, engagement_id=engagement_id)
        except ScanParseError as exc:
            raise HTTPException(400, detail=str(exc)) from exc
    finally:
        await file.close()
    return mutation_response(request, f"/e/{engagement_id}/scans")


@router.get("/diff", response_model=DiffResponse)
def diff(a: int | None = None, b: int | None = None, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> JSONResponse:
    rows = session.exec(select(Scan).where(Scan.engagement_id == engagement_id).order_by(col(Scan.imported_at).desc())).all()
    for scan_id in (a, b):
        if scan_id is not None and queries.get_owned(session, Scan, scan_id, engagement_id=engagement_id) is None:
            raise HTTPException(404, detail="scan not found")
    result = queries.diff_scans(session, a, b, engagement_id=engagement_id) if a and b else None
    return JSONResponse(encode_page({"scans": rows, "result": result, "a": a, "b": b}))


@router.get("/annotation", response_model=AnnotationContextResponse)
def annotation_get(host_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> JSONResponse:
    owned_host(session, host_id, engagement_id)
    return JSONResponse(encode_page({"host_id": host_id, "ann": queries.get_annotation(session, host_id=host_id, engagement_id=engagement_id), "statuses": list(Status), "saved": False}))


@router.put("/annotation", response_model=MutationResponse, response_model_exclude_unset=True)
def replace_annotation(host_id: int = Form(...), status: Status = Form(Status.new), tags: str = Form(""), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> dict[str, bool]:
    owned_host(session, host_id, engagement_id)
    queries.upsert_annotation(session, status, [tag.strip() for tag in tags.split(",") if tag.strip()], host_id=host_id, engagement_id=engagement_id)
    return {"ok": True}


@router.post("/notes", response_model=MutationResponse, response_model_exclude_unset=True)
def note_create(host_id: int = Form(...), title: str = Form(""), body_md: str = Form(""), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> dict[str, bool]:
    owned_host(session, host_id, engagement_id)
    session.add(Note(host_id=host_id, title=title.strip() or "Untitled", body_md=body_md, engagement_id=engagement_id))
    session.commit()
    return {"ok": True}


@router.put("/notes/{note_id}", response_model=MutationResponse, response_model_exclude_unset=True)
def note_edit(note_id: int, title: str = Form(""), body_md: str = Form(""), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> dict[str, bool]:
    note = queries.get_owned(session, Note, note_id, engagement_id=engagement_id)
    if note is None:
        raise HTTPException(404, detail="note not found")
    note.title = title.strip() or "Untitled"
    note.body_md = body_md
    note.updated_at = datetime.now(UTC)
    session.commit()
    return {"ok": True}


@router.delete("/notes/{note_id}", response_model=MutationResponse, response_model_exclude_unset=True)
def note_delete(note_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> dict[str, bool]:
    note = queries.get_owned(session, Note, note_id, engagement_id=engagement_id)
    if note is None:
        raise HTTPException(404, detail="note not found")
    session.delete(note)
    session.commit()
    return {"ok": True}
