"""FastAPI app: server-rendered Jinja2 + HTMX. No frontend build."""

from __future__ import annotations

import csv
import html
import io
import ipaddress
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from sqlmodel import Session, select

from penrecon import queries
from penrecon.db import ATTACHMENTS_DIR, get_session, init_db
from penrecon.ingest import _upsert_hostname, ingest_scan
from penrecon.models import (
    Attachment,
    CredKind,
    Credential,
    CredentialHost,
    CredentialService,
    Host,
    HostHostname,
    Note,
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
# cache-bust /static assets by mtime so CSS/JS edits show up on refresh, no hard-reload needed
templates.env.globals["asset_ver"] = lambda name: int((_HERE / "static" / name).stat().st_mtime)


def _highlight(text: str, q: str) -> Markup:
    """Escape ``text`` and wrap each case-insensitive occurrence of ``q`` in
    <mark>. Returns Markup so Jinja doesn't re-escape the tags we added."""
    q = q.strip()
    if not q:
        return Markup(escape(text))
    lo, ql, out, i = text.lower(), q.lower(), [], 0
    while (j := lo.find(ql, i)) >= 0:
        out.append(escape(text[i:j]))
        out.append(Markup("<mark>") + escape(text[j : j + len(ql)]) + Markup("</mark>"))
        i = j + len(ql)
    out.append(escape(text[i:]))
    return Markup("").join(out)


templates.env.filters["highlight"] = _highlight

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
    change: str = "",  # "" | "new" | "changed" — filter to hosts that moved since last scan
    sort: str = "ip",
    dir: str = "",  # sort direction; empty falls back to the column's natural default
    page: str = "1",  # str, tolerate empty/garbage from the URL; parsed + clamped below
    session: Session = Depends(get_session),
) -> HTMLResponse:
    port_val = int(port) if port.strip().isdigit() else None
    direction = dir if dir in ("asc", "desc") else queries.SORT_DEFAULT_DIR.get(sort, "asc")
    page_no = int(page) if page.strip().isdigit() else 1
    all_rows = queries.host_rows(session)
    rows = queries.filter_hosts(
        all_rows, q=q, port=port_val, tag=tag, status=status, change=change
    )
    rows = queries.sort_hosts(rows, sort, direction)
    matched = len(rows)
    page_rows, page_no, pages = queries.paginate(rows, page_no)
    ctx = {"request": request, "rows": page_rows, "total": len(all_rows), "matched": matched,
           "page": page_no, "pages": pages, "per_page": queries.HOSTS_PER_PAGE,
           "q": q, "port": port, "tag": tag, "status": status, "change": change,
           "sort": sort, "direction": direction, "statuses": list(Status)}
    tpl = "_host_table.html" if _is_htmx(request) else "index.html"
    return templates.TemplateResponse(request, tpl, ctx)


@app.get("/search", response_class=HTMLResponse)
def search_page(
    request: Request, q: str = "", session: Session = Depends(get_session)
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "search.html",
        {"request": request, "q": q.strip(), "results": queries.search(session, q)},
    )


@app.get("/export/hosts.csv")
def export_hosts_csv(session: Session = Depends(get_session)) -> Response:
    """Full host/service inventory as CSV — one row per service."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=queries.EXPORT_COLUMNS)
    writer.writeheader()
    writer.writerows(queries.export_rows(session))
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="penrecon-hosts-{stamp}.csv"'},
    )


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
            "host_notes": queries.notes_for(session, TargetType.host, host_id),
            "host_attachments": queries.attachments_for(session, TargetType.host, host_id),
            "attachments_by_service": {
                s.service_id: queries.attachments_for(session, TargetType.service, s.service_id)
                for s in services
            },
            "notes_by_service": {
                s.service_id: queries.notes_for(session, TargetType.service, s.service_id)
                for s in services
            },
            "statuses": list(Status),
            "states": list(ObsState),
            "host_credentials": queries.credentials_for_host(session, host_id),
            "kinds": list(CredKind),
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
            "notes_by_service": {
                s.service_id: queries.notes_for(session, TargetType.service, s.service_id)
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

def _normalize_ip(raw: str) -> str | None:
    """Canonical IP string if ``raw`` is a valid IPv4/IPv6 address, else ``None``.
    ``ipaddress`` is the trust-boundary authority — the client is never trusted to
    have validated. Canonicalizing (e.g. ``2001:0DB8::1`` → ``2001:db8::1``) keeps
    the unique-IP dedupe consistent regardless of how the operator typed it."""
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return None


def _invalid_ip_response(raw: str, back: str) -> HTMLResponse:
    safe = html.escape(raw)
    return HTMLResponse(
        f'<p>"{safe}" is not a valid IPv4 or IPv6 address.</p>'
        f'<p><a href="{html.escape(back)}">Back</a></p>',
        status_code=400,
    )


@app.post("/hosts")
def create_host(
    ip: str = Form(...), session: Session = Depends(get_session)
) -> Response:
    clean = ip.strip()
    if not clean:
        return RedirectResponse("/", status_code=303)
    norm = _normalize_ip(clean)
    if norm is None:
        return _invalid_ip_response(clean, "/")
    existing = session.exec(select(Host).where(Host.ip == norm)).first()
    if existing is not None:
        return RedirectResponse(f"/hosts/{existing.id}", status_code=303)
    now = datetime.now(UTC)
    host = Host(ip=norm, first_seen=now, last_seen=now)
    session.add(host)
    session.commit()
    session.refresh(host)
    return RedirectResponse(f"/hosts/{host.id}", status_code=303)


@app.post("/hosts/{host_id}/edit")
def edit_host(
    host_id: int, ip: str = Form(...), session: Session = Depends(get_session)
) -> Response:
    host = session.get(Host, host_id)
    if host is None:
        return RedirectResponse("/", status_code=303)
    clean = ip.strip()
    if not clean:  # empty = leave the IP unchanged
        return RedirectResponse(f"/hosts/{host_id}", status_code=303)
    norm = _normalize_ip(clean)
    if norm is None:
        return _invalid_ip_response(clean, f"/hosts/{host_id}")
    if norm != host.ip:
        dup = session.exec(select(Host).where(Host.ip == norm)).first()
        if dup is None:  # don't collide with another host's IP
            host.ip = norm
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
        for note in queries.notes_for(session, TargetType.service, sid):
            session.delete(note)
        for csl in session.exec(
            select(CredentialService).where(CredentialService.service_id == sid)
        ).all():
            session.delete(csl)  # drop credential↔service links (credential itself survives)
    for chl in session.exec(
        select(CredentialHost).where(CredentialHost.host_id == host_id)
    ).all():
        session.delete(chl)
    host_ann = queries.get_annotation(session, TargetType.host, host_id)
    if host_ann is not None:
        session.delete(host_ann)
    for note in queries.notes_for(session, TargetType.host, host_id):
        session.delete(note)
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
    status: Status = Form(Status.new),
    tags: str = Form(""),
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
    # one Save persists both the scan overrides and the triage annotation
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    queries.upsert_annotation(session, TargetType.service, service_id, status, tag_list)
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
    for note in queries.notes_for(session, TargetType.service, service_id):
        session.delete(note)
    for csl in session.exec(
        select(CredentialService).where(CredentialService.service_id == service_id)
    ).all():
        session.delete(csl)  # drop credential↔service links (credential itself survives)
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


# --- credentials --------------------------------------------------------------

def _render_credentials(request: Request, session: Session) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "_credentials.html",
        {
            "request": request,
            "credentials": queries.credential_views(session),
            "hosts": session.exec(select(Host).order_by(Host.ip)).all(),
            "services": queries.service_picker(session),
        },
    )


def _render_host_credentials(
    request: Request, session: Session, host_id: int
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "_host_credentials.html",
        {
            "request": request,
            "host": session.get(Host, host_id),
            "host_credentials": queries.credentials_for_host(session, host_id),
            "kinds": list(CredKind),
        },
    )


@app.post("/credentials/{cred_id}/edit", response_class=HTMLResponse)
def edit_credential(
    request: Request,
    cred_id: int,
    kind: str = Form("password"),
    username: str = Form(""),
    secret: str = Form(""),
    notes: str = Form(""),
    host_id: int | None = Form(None),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    cred = session.get(Credential, cred_id)
    if cred is not None:
        try:
            cred.kind = CredKind(kind)
        except ValueError:
            cred.kind = CredKind.password
        cred.username = username.strip()
        cred.secret = secret.strip()
        cred.notes = notes.strip()
        session.commit()
    if host_id is not None:
        return _render_host_credentials(request, session, host_id)
    return _render_credentials(request, session)


@app.get("/credentials", response_class=HTMLResponse)
def credentials_page(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "credentials.html",
        {
            "request": request,
            "credentials": queries.credential_views(session),
            "hosts": session.exec(select(Host).order_by(Host.ip)).all(),
            "services": queries.service_picker(session),
            "kinds": list(CredKind),
        },
    )


@app.post("/credentials", response_class=HTMLResponse)
def create_credential(
    request: Request,
    kind: str = Form("password"),
    username: str = Form(""),
    secret: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    user, sec = username.strip(), secret.strip()
    if user or sec:  # a credential must carry at least a username or a secret
        try:
            k = CredKind(kind)
        except ValueError:
            k = CredKind.password
        session.add(Credential(kind=k, username=user, secret=sec, notes=notes.strip()))
        session.commit()
    return _render_credentials(request, session)


@app.post("/credentials/{cred_id}/delete", response_class=HTMLResponse)
def delete_credential(
    request: Request,
    cred_id: int,
    host_id: int | None = Form(None),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    cred = session.get(Credential, cred_id)
    if cred is not None:
        for hl in session.exec(
            select(CredentialHost).where(CredentialHost.credential_id == cred_id)
        ).all():
            session.delete(hl)
        for sl in session.exec(
            select(CredentialService).where(CredentialService.credential_id == cred_id)
        ).all():
            session.delete(sl)
        session.delete(cred)
        session.commit()
    if host_id is not None:  # deleted from a host panel — re-render just that panel
        return _render_host_credentials(request, session, host_id)
    return _render_credentials(request, session)


@app.post("/credentials/{cred_id}/link/host", response_class=HTMLResponse)
def link_cred_host(
    request: Request, cred_id: int, host_id: str = Form(""), session: Session = Depends(get_session)
) -> HTMLResponse:
    hid = int(host_id) if host_id.strip().isdigit() else None
    valid = hid is not None and session.get(Credential, cred_id) is not None and session.get(Host, hid) is not None
    if valid and hid is not None and session.get(CredentialHost, (cred_id, hid)) is None:
        session.add(CredentialHost(credential_id=cred_id, host_id=hid))  # ignore duplicate links
        session.commit()
    return _render_credentials(request, session)


@app.post("/credentials/{cred_id}/unlink/host/{host_id}", response_class=HTMLResponse)
def unlink_cred_host(
    request: Request, cred_id: int, host_id: int, session: Session = Depends(get_session)
) -> HTMLResponse:
    link = session.get(CredentialHost, (cred_id, host_id))
    if link is not None:
        session.delete(link)
        session.commit()
    return _render_credentials(request, session)


@app.post("/credentials/{cred_id}/link/service", response_class=HTMLResponse)
def link_cred_service(
    request: Request,
    cred_id: int,
    service_id: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    sid = int(service_id) if service_id.strip().isdigit() else None
    valid = sid is not None and session.get(Credential, cred_id) is not None and session.get(Service, sid) is not None
    if valid and sid is not None and session.get(CredentialService, (cred_id, sid)) is None:
        session.add(CredentialService(credential_id=cred_id, service_id=sid))
        session.commit()
    return _render_credentials(request, session)


@app.post("/credentials/{cred_id}/unlink/service/{service_id}", response_class=HTMLResponse)
def unlink_cred_service(
    request: Request, cred_id: int, service_id: int, session: Session = Depends(get_session)
) -> HTMLResponse:
    link = session.get(CredentialService, (cred_id, service_id))
    if link is not None:
        session.delete(link)
        session.commit()
    return _render_credentials(request, session)


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
    status: Status = Form(Status.new),
    tags: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    queries.upsert_annotation(session, target_type, target_id, status, tag_list)
    return _render_annotation(request, session, target_type, target_id, saved=True)


# --- notes: any number of titled notes per entity -----------------------------

def _render_notes(request: Request, session: Session, tt: TargetType, tid: int) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "_notes.html",
        {
            "request": request,
            "tt": tt.value,
            "tid": tid,
            "notes": queries.notes_for(session, tt, tid),
        },
    )


@app.post("/notes", response_class=HTMLResponse)
def note_create(
    request: Request,
    target_type: TargetType = Form(...),
    target_id: int = Form(...),
    title: str = Form(""),
    body_md: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    clean_title = title.strip() or "Untitled"  # a note always has a title
    session.add(
        Note(target_type=target_type, target_id=target_id, title=clean_title, body_md=body_md)
    )
    session.commit()
    return _render_notes(request, session, target_type, target_id)


@app.post("/notes/{note_id}/edit", response_class=HTMLResponse)
def note_edit(
    request: Request,
    note_id: int,
    title: str = Form(""),
    body_md: str = Form(""),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    note = session.get(Note, note_id)
    if note is None:
        return HTMLResponse("note not found", status_code=404)
    note.title = title.strip() or "Untitled"
    note.body_md = body_md
    note.updated_at = datetime.now(UTC)
    session.commit()
    return _render_notes(request, session, note.target_type, note.target_id)


@app.post("/notes/{note_id}/delete", response_class=HTMLResponse)
def note_delete(
    request: Request, note_id: int, session: Session = Depends(get_session)
) -> HTMLResponse:
    note = session.get(Note, note_id)
    if note is None:
        return HTMLResponse("note not found", status_code=404)
    tt, tid = note.target_type, note.target_id
    session.delete(note)
    session.commit()
    return _render_notes(request, session, tt, tid)


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
