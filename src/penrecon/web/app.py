"""FastAPI app: server-rendered Jinja2 + HTMX. No frontend build."""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from penrecon import queries
from penrecon.db import ATTACHMENTS_DIR, get_session, init_db
from penrecon.ingest import _upsert_hostname, ingest_scan
from penrecon.models import (
    Annotation,
    Attachment,
    Host,
    HostHostname,
    Observation,
    ObsState,
    Scan,
    Service,
    Status,
    TargetType,
)
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
    port: str = "",  # str, not int|None: the form submits an empty port= which 422s an int
    tag: str = "",
    status: str = "",
    sort: str = "ip",
    session: Session = Depends(get_session),
) -> HTMLResponse:
    port_val = int(port) if port.strip().isdigit() else None
    rows = queries.filter_hosts(
        queries.host_rows(session), q=q, port=port_val, tag=tag, status=status
    )
    rows = queries.sort_hosts(rows, sort)
    ctx = {"request": request, "rows": rows, "q": q, "port": port, "tag": tag, "status": status,
           "sort": sort, "statuses": list(Status)}
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
            "hostnames": queries.host_hostnames(session, host_id),
            "services": services,
            "host_ann": queries.get_annotation(session, TargetType.host, host_id),
            "host_attachments": queries.attachments_for(session, TargetType.host, host_id),
            "attachments_by_service": {
                s.service_id: queries.attachments_for(session, TargetType.service, s.service_id)
                for s in services
            },
            "statuses": list(Status),
            "states": list(ObsState),
        },
    )


def _render_hostnames(request: Request, session: Session, host: Host) -> HTMLResponse:
    assert host.id is not None
    return templates.TemplateResponse(
        request,
        "_hostnames.html",
        {"request": request, "host": host, "hostnames": queries.host_hostnames(session, host.id)},
    )


def _render_services(request: Request, session: Session, host: Host) -> HTMLResponse:
    assert host.id is not None
    services = queries.host_services(session, host.id)
    return templates.TemplateResponse(
        request,
        "_services.html",
        {
            "request": request,
            "host": host,
            "services": services,
            "attachments_by_service": {
                s.service_id: queries.attachments_for(session, TargetType.service, s.service_id)
                for s in services
            },
            "statuses": list(Status),
            "states": list(ObsState),
        },
    )


@app.post("/hosts/{host_id}/hostnames", response_class=HTMLResponse)
def add_hostname(
    request: Request,
    host_id: int,
    name: str = Form(...),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    host = session.get(Host, host_id)
    if host is None:
        return HTMLResponse("host not found", status_code=404)
    clean = name.strip().lower()  # normalize so manual adds dedup against scan data
    if clean:
        _upsert_hostname(session, host_id, clean, datetime.now(UTC))
        session.commit()
    return _render_hostnames(request, session, host)


@app.post("/hosts/{host_id}/hostnames/{hostname_id}/delete", response_class=HTMLResponse)
def delete_hostname(
    request: Request, host_id: int, hostname_id: int, session: Session = Depends(get_session)
) -> HTMLResponse:
    host = session.get(Host, host_id)
    if host is None:
        return HTMLResponse("host not found", status_code=404)
    link = session.get(HostHostname, (host_id, hostname_id))
    if link is not None:
        link.hidden = True  # sticky: a re-scan won't bring it back
        session.commit()
    return _render_hostnames(request, session, host)


# --- manual host + service CRUD -----------------------------------------------

@app.post("/hosts")
def create_host(ip: str = Form(...), session: Session = Depends(get_session)) -> RedirectResponse:
    clean = ip.strip()
    existing = session.exec(select(Host).where(Host.ip == clean)).first() if clean else None
    if existing is not None:
        return RedirectResponse(f"/hosts/{existing.id}", status_code=303)
    if not clean:
        return RedirectResponse("/", status_code=303)
    now = datetime.now(UTC)
    host = Host(ip=clean, first_seen=now, last_seen=now)
    session.add(host)
    session.commit()
    session.refresh(host)
    return RedirectResponse(f"/hosts/{host.id}", status_code=303)


@app.post("/hosts/{host_id}/edit")
def edit_host(
    host_id: int, ip: str = Form(...), session: Session = Depends(get_session)
) -> RedirectResponse:
    host = session.get(Host, host_id)
    if host is None:
        return RedirectResponse("/", status_code=303)
    clean = ip.strip()
    if clean and clean != host.ip:
        dup = session.exec(select(Host).where(Host.ip == clean)).first()
        if dup is None:  # don't collide with another host's IP
            host.ip = clean
            session.commit()
    return RedirectResponse(f"/hosts/{host_id}", status_code=303)


@app.post("/hosts/{host_id}/delete")
def delete_host(host_id: int, session: Session = Depends(get_session)) -> RedirectResponse:
    host = session.get(Host, host_id)
    if host is None:
        return RedirectResponse("/", status_code=303)
    svc_ids = [s.id for s in session.exec(select(Service).where(Service.host_id == host_id)).all()]
    for att in queries.attachments_for(session, TargetType.host, host_id):
        session.delete(att)
    for sid in svc_ids:
        if sid is None:
            continue
        for att in queries.attachments_for(session, TargetType.service, sid):
            session.delete(att)
        ann = queries.get_annotation(session, TargetType.service, sid)
        if ann is not None:
            session.delete(ann)
    host_ann = queries.get_annotation(session, TargetType.host, host_id)
    if host_ann is not None:
        session.delete(host_ann)
    for row in session.exec(select(Observation).where(Observation.host_id == host_id)).all():
        session.delete(row)
    for svc in session.exec(select(Service).where(Service.host_id == host_id)).all():
        session.delete(svc)
    for link in session.exec(select(HostHostname).where(HostHostname.host_id == host_id)).all():
        session.delete(link)
    session.delete(host)
    session.commit()
    return RedirectResponse("/", status_code=303)


def _clean(value: str) -> str | None:
    v = value.strip()
    return v or None


@app.post("/hosts/{host_id}/services", response_class=HTMLResponse)
def add_service(
    request: Request,
    host_id: int,
    port: int = Form(...),
    proto: str = Form("tcp"),
    state: str = Form("open"),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    host = session.get(Host, host_id)
    if host is None:
        return HTMLResponse("host not found", status_code=404)
    svc = session.exec(
        select(Service).where(
            Service.host_id == host_id, Service.port == port, Service.proto == proto.strip().lower()
        )
    ).first()
    if svc is None:
        svc = Service(host_id=host_id, port=port, proto=proto.strip().lower())
        session.add(svc)
    svc.m_state = ObsState(state) if state else ObsState.open
    svc.m_service_name = _clean(service_name)
    svc.m_product = _clean(product)
    svc.m_version = _clean(version)
    session.commit()
    return _render_services(request, session, host)


@app.post("/services/{service_id}/edit", response_class=HTMLResponse)
def edit_service(
    request: Request,
    service_id: int,
    state: str = Form(""),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    svc = session.get(Service, service_id)
    if svc is None:
        return HTMLResponse("service not found", status_code=404)
    svc.m_state = ObsState(state) if state else None  # blank reverts to scan value
    svc.m_service_name = _clean(service_name)
    svc.m_product = _clean(product)
    svc.m_version = _clean(version)
    session.commit()
    host = session.get(Host, svc.host_id)
    assert host is not None
    return _render_services(request, session, host)


@app.post("/services/{service_id}/delete", response_class=HTMLResponse)
def delete_service(
    request: Request, service_id: int, session: Session = Depends(get_session)
) -> HTMLResponse:
    svc = session.get(Service, service_id)
    if svc is None:
        return HTMLResponse("service not found", status_code=404)
    host = session.get(Host, svc.host_id)
    assert host is not None
    # hard delete: the service and everything tied to it. A later scan that sees
    # this port re-creates it fresh, as if it had never been deleted.
    ann = queries.get_annotation(session, TargetType.service, service_id)
    if ann is not None:
        session.delete(ann)
    for att in queries.attachments_for(session, TargetType.service, service_id):
        Path(att.stored_path).unlink(missing_ok=True)
        session.delete(att)
    for obs in session.exec(
        select(Observation).where(
            Observation.host_id == svc.host_id,
            Observation.port == svc.port,
            Observation.proto == svc.proto,
        )
    ).all():
        session.delete(obs)
    session.delete(svc)
    session.commit()
    return _render_services(request, session, host)


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
