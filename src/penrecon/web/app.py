"""FastAPI app: server-rendered Jinja2 + HTMX. No frontend build."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from penrecon import queries
from penrecon.db import ATTACHMENTS_DIR, get_session, init_db
from penrecon.ingest import ingest_scan
from penrecon.models import Annotation, Attachment, Host, Scan, Status, TargetType
from penrecon.parsers import PARSERS

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))

app = FastAPI(title="penrecon")
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


@app.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    q: str = "",
    port: int | None = None,
    tag: str = "",
    status: str = "",
    session: Session = Depends(get_session),
) -> HTMLResponse:
    rows = queries.filter_hosts(queries.host_rows(session), q=q, port=port, tag=tag, status=status)
    ctx = {"request": request, "rows": rows, "q": q, "port": port, "tag": tag, "status": status,
           "statuses": list(Status)}
    tpl = "_host_table.html" if _is_htmx(request) else "index.html"
    return templates.TemplateResponse(request, tpl, ctx)


@app.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(
    request: Request, host_id: int, session: Session = Depends(get_session)
) -> HTMLResponse:
    host = session.get(Host, host_id)
    if host is None:
        return HTMLResponse("host not found", status_code=404)
    services = queries.host_services(session, host_id)
    return templates.TemplateResponse(
        request,
        "host.html",
        {
            "request": request,
            "host": host,
            "hostnames": queries._hostnames_for(session, host_id),
            "services": services,
            "host_ann": queries.get_annotation(session, TargetType.host, host_id),
            "host_attachments": queries.attachments_for(session, TargetType.host, host_id),
            "attachments_by_service": {
                s.service_id: queries.attachments_for(session, TargetType.service, s.service_id)
                for s in services
            },
            "statuses": list(Status),
        },
    )


@app.get("/scans", response_class=HTMLResponse)
def scans(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    rows = session.exec(select(Scan).order_by(Scan.imported_at.desc())).all()  # type: ignore[attr-defined]
    return templates.TemplateResponse(
        request, "scans.html", {"request": request, "scans": rows, "tools": sorted(PARSERS)}
    )


@app.post("/scans")
async def upload_scan(
    file: UploadFile, tool: str = Form("nmap"), session: Session = Depends(get_session)
) -> RedirectResponse:
    data = await file.read()
    ingest_scan(session, data, file.filename or "upload", tool)
    return RedirectResponse("/scans", status_code=303)


@app.get("/diff", response_class=HTMLResponse)
def diff(
    request: Request,
    a: int | None = None,
    b: int | None = None,
    session: Session = Depends(get_session),
) -> HTMLResponse:
    all_scans = session.exec(select(Scan).order_by(Scan.imported_at.desc())).all()  # type: ignore[attr-defined]
    result = queries.diff_scans(session, a, b) if a and b else None
    return templates.TemplateResponse(
        request,
        "diff.html",
        {"request": request, "scans": all_scans, "result": result, "a": a, "b": b},
    )


def _render_annotation(
    request: Request, session: Session, tt: TargetType, tid: int, saved: bool = False
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "_annotation.html",
        {
            "request": request,
            "tt": tt.value,
            "tid": tid,
            "ann": queries.get_annotation(session, tt, tid),
            "statuses": list(Status),
            "saved": saved,
        },
    )


@app.get("/annotation", response_class=HTMLResponse)
def annotation_get(
    request: Request,
    target_type: TargetType,
    target_id: int,
    session: Session = Depends(get_session),
) -> HTMLResponse:
    return _render_annotation(request, session, target_type, target_id)


@app.post("/annotation", response_class=HTMLResponse)
def annotation_post(
    request: Request,
    target_type: TargetType = Form(...),
    target_id: int = Form(...),
    body_md: str = Form(""),
    status: Status = Form(Status.new),
    tags: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    ann = queries.get_annotation(session, target_type, target_id)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    if ann is None:
        ann = Annotation(target_type=target_type, target_id=target_id)
        session.add(ann)
    ann.body_md = body_md
    ann.status = status
    ann.tags = tag_list
    session.commit()
    return _render_annotation(request, session, target_type, target_id, saved=True)


@app.post("/attachment", response_class=HTMLResponse)
async def attachment_post(
    request: Request,
    target_type: TargetType = Form(...),
    target_id: int = Form(...),
    file: UploadFile = ...,  # type: ignore[assignment]
    session: Session = Depends(get_session),
) -> HTMLResponse:
    stored = f"{uuid.uuid4().hex}_{file.filename}"
    dest = ATTACHMENTS_DIR / stored
    with dest.open("wb") as fh:
        shutil.copyfileobj(file.file, fh)
    session.add(
        Attachment(
            target_type=target_type,
            target_id=target_id,
            filename=file.filename or stored,
            stored_path=str(dest),
            content_type=file.content_type,
            size=dest.stat().st_size,
        )
    )
    session.commit()
    return templates.TemplateResponse(
        request,
        "_attachments.html",
        {
            "request": request,
            "tt": target_type.value,
            "tid": target_id,
            "attachments": queries.attachments_for(session, target_type, target_id),
        },
    )


@app.get("/attachment/{attachment_id}")
def attachment_get(
    attachment_id: int, session: Session = Depends(get_session)
) -> FileResponse:
    att = session.get(Attachment, attachment_id)
    if att is None:
        return FileResponse("/dev/null", status_code=404)
    return FileResponse(att.stored_path, filename=att.filename, media_type=att.content_type)
