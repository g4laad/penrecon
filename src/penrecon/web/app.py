"""FastAPI routes and the React application page-data boundary."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import shutil
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, col, select

from penrecon import queries
from penrecon.db import DATA_DIR, engagement_attachments_dir, get_session, init_db
from penrecon.ingest import ScanParseError, ingest_scan
from penrecon.inventory import link_hostname
from penrecon.models import (
    CredKind,
    Credential,
    CredentialHost,
    CredentialService,
    Engagement,
    Host,
    HostHostname,
    Note,
    Observation,
    ObsState,
    OperationLog,
    Scan,
    Service,
    Status,
)
from penrecon.parsers import PARSERS

_HERE = Path(__file__).parent


def page_response(request: Request, context: dict[str, object]) -> Response:
    """Return the same page data to JSON consumers and the local React shell."""
    data = jsonable_encoder({
        **context,
        "engagement": getattr(request.state, "engagement", None),
        "engagements": getattr(request.state, "engagements", []),
        "per_page_choices": [str(size) for size in queries.PER_PAGE_OPTIONS] + ["all"],
    })
    headers = {"Vary": "Accept"}
    if "application/json" in request.headers.get("accept", "").lower():
        return JSONResponse(data, headers=headers)
    # Escape HTML-significant characters even inside a non-executable script:
    # the HTML parser still recognizes a literal </script> in JSON strings.
    serialized = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    for char, escaped in (
        ("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
        ("\u2028", "\\u2028"), ("\u2029", "\\u2029"),
    ):
        serialized = serialized.replace(char, escaped)
    # Rebuilt bundles keep fixed filenames; change their URLs on every rebuild
    # so normal navigation cannot reuse a cached, obsolete layout.
    css_version = (_HERE / "static/ui/app.css").stat().st_mtime_ns
    js_version = (_HERE / "static/ui/app.js").stat().st_mtime_ns
    return HTMLResponse(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>penrecon</title><link rel="stylesheet" href="/static/ui/app.css?v={css_version}">'
        '</head><body><div id="root"></div>'
        f'<script id="page-data" type="application/json">{serialized}</script>'
        f'<script type="module" src="/static/ui/app.js?v={js_version}"></script></body></html>',
        headers=headers,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title="penrecon", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")


def require_engagement(
    request: Request, engagement_id: str, session: Session = Depends(get_session)
) -> str:
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    request.state.engagement = engagement
    request.state.engagements = session.exec(
        select(Engagement).order_by(col(Engagement.created_at).desc())
    ).all()
    return engagement_id


scoped = APIRouter(prefix="/e/{engagement_id}")


@app.get("/")
def landing() -> RedirectResponse:
    return RedirectResponse("/engagements", status_code=303)


@app.get("/engagements", response_class=HTMLResponse)
def engagements_page(request: Request, session: Session = Depends(get_session)) -> Response:
    sort = request.query_params.get("sort", "created_at")
    if sort not in ("name", "created_at"):
        sort = "created_at"
    direction = request.query_params.get("dir", "")
    if direction not in ("asc", "desc"):
        direction = "asc" if sort == "name" else "desc"
    order = col(Engagement.name).collate("NOCASE") if sort == "name" else col(Engagement.created_at)
    request.state.engagements = session.exec(
        select(Engagement).order_by(
            order.desc() if direction == "desc" else order.asc(),
            col(Engagement.id).asc(),
        )
    ).all()
    return page_response(request, {"sort": sort, "direction": direction})


@app.post("/engagements")
def create_engagement(
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
) -> Response:
    clean_name = name.strip()
    if not clean_name:
        return JSONResponse(
            {"detail": "Enter an engagement name.", "field_errors": {"name": "Enter an engagement name."}},
            status_code=400,
        )
    engagement = Engagement(name=clean_name, description=description.strip())
    session.add(engagement)
    session.commit()
    session.refresh(engagement)
    return RedirectResponse(f"/e/{engagement.id}/", status_code=303)


@app.post("/engagements/{engagement_id}/edit")
def edit_engagement(
    engagement_id: str,
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
) -> Response:
    engagement = session.get(Engagement, engagement_id)
    if engagement is None:
        return JSONResponse({"detail": "engagement not found"}, status_code=404)
    clean_name = name.strip()
    if not clean_name:
        return JSONResponse(
            {"detail": "Enter an engagement name.", "field_errors": {"name": "Enter an engagement name."}},
            status_code=400,
        )
    engagement.name = clean_name
    engagement.description = description.strip()
    session.add(engagement)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    q: str = "",
    port: str = "",  # str: forms submit empty values
    tag: str = "",
    status: str = "",
    change: str = "",
    sort: str = "change",
    dir: str = "",
    page: str = "1",
    per: str = "",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    port_val = int(port) if port.strip().isdigit() else None
    direction = dir if dir in ("asc", "desc") else queries.SORT_DEFAULT_DIR.get(sort, "asc")
    page_no = int(page) if page.strip().isdigit() else 1
    per_limit = queries.resolve_per_page(per)
    fit = request.query_params.get("fit", "")
    if len(fit) <= 2 and fit.isascii() and fit.isdecimal() and 1 <= int(fit) <= 50:
        per_limit = int(fit)
    all_rows = queries.host_rows(session, engagement_id=engagement_id)
    rows = queries.filter_hosts(
        all_rows, q=q, port=port_val, tag=tag, status=status, change=change
    )
    rows = queries.sort_hosts(rows, sort, direction)
    matched = len(rows)
    page_rows, page_no, pages = queries.paginate(rows, page_no, per_limit)
    ctx: dict[str, object] = {"rows": page_rows, "total": len(all_rows), "matched": matched,
           "page": page_no, "pages": pages, "per_page": per_limit or matched,
           "per": "all" if per_limit is None else str(per_limit),
           "q": q, "port": port, "tag": tag, "status": status, "change": change,
           "sort": sort, "direction": direction, "statuses": list(Status)}
    return page_response(request, ctx)


@scoped.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "", engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    return page_response(request, {"q": q.strip(), "results": queries.search(session, q, engagement_id=engagement_id)})


@scoped.get("/export/hosts.csv")
def export_hosts_csv(engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    """Full host/service inventory as CSV — one row per service."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=queries.EXPORT_COLUMNS)
    writer.writeheader()
    writer.writerows(queries.export_rows(session, engagement_id=engagement_id))
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="penrecon-hosts-{stamp}.csv"'},
    )


@dataclass(frozen=True)
class _ServiceTable:
    """URL/form state carried unchanged through service mutations."""

    sort: str = "port"
    dir: str = ""
    page: str = "1"
    f_port: str = ""
    f_state: str = ""
    f_service: str = ""
    f_status: str = ""
    per: str = ""


def _service_table_form(
    sort: str = Form("port"),
    dir: str = Form(""),
    page: str = Form("1"),
    f_port: str = Form(""),
    f_state: str = Form(""),
    f_service: str = Form(""),
    f_status: str = Form(""),
    per: str = Form(""),
) -> _ServiceTable:
    return _ServiceTable(sort, dir, page, f_port, f_state, f_service, f_status, per)


def _services_ctx(
    session: Session, host: Host, table: _ServiceTable,
    *, engagement_id: str,
) -> dict[str, object]:
    """Filtered, sorted, server-paginated services; svc_total is the matched count."""
    assert host.id is not None
    services = queries.resolved_services(session, host.id, engagement_id=engagement_id)
    services = queries.filter_services(
        services, table.f_port, table.f_state, table.f_service, table.f_status
    )
    direction = (
        table.dir if table.dir in ("asc", "desc")
        else queries.SERVICE_SORT_DEFAULT_DIR.get(table.sort, "asc")
    )
    services = queries.sort_services(services, table.sort, direction)
    total = len(services)
    page_no = int(table.page) if table.page.strip().isdigit() else 1
    per_limit = queries.resolve_per_page(table.per)
    page_services, page_no, pages = queries.paginate(services, page_no, per_limit)
    return {"host": host, "services": page_services, "svc_total": total,
            "page": page_no, "pages": pages, "sort": table.sort, "direction": direction,
            "per": "all" if per_limit is None else str(per_limit),
            "f_port": table.f_port, "f_state": table.f_state,
            "f_service": table.f_service, "f_status": table.f_status,
            "statuses": list(Status), "states": list(ObsState)}


@scoped.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(
    request: Request,
    host_id: int,
    table: _ServiceTable = Depends(_ServiceTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    svc_ctx = _services_ctx(session, host, table, engagement_id=engagement_id)
    return page_response(request, {
        "hostnames": queries.host_hostnames(session, host_id, engagement_id=engagement_id),
        "host_ann": queries.get_annotation(session, host_id=host_id, engagement_id=engagement_id),
        "host_notes": queries.notes_for(session, host_id, engagement_id=engagement_id),
        "host_credentials": queries.credentials_for_host(session, host_id, engagement_id=engagement_id),
        "kinds": list(CredKind),
        **svc_ctx,
    })


def _hostnames_response(request: Request, session: Session, host: Host, *, engagement_id: str) -> Response:
    assert host.id is not None
    return page_response(request, {"host": host, "hostnames": queries.host_hostnames(session, host.id, engagement_id=engagement_id)})


def _services_response(
    request: Request, session: Session, host: Host, table: _ServiceTable,
    *, engagement_id: str,
) -> Response:
    return page_response(
        request, _services_ctx(session, host, table, engagement_id=engagement_id)
    )


@scoped.post("/hosts/{host_id}/hostnames", response_class=JSONResponse)
def add_hostname(
    request: Request,
    host_id: int,
    name: str = Form(...),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    clean = name.strip().lower()  # normalize so manual adds dedup against scan data
    if clean:
        link_hostname(session, host_id, clean, datetime.now(UTC), engagement_id=engagement_id)
        session.commit()
    return _hostnames_response(request, session, host, engagement_id=engagement_id)


@scoped.post("/hosts/{host_id}/hostnames/{hostname_id}/delete", response_class=JSONResponse)
def delete_hostname(request: Request, host_id: int, hostname_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    link = queries.get_owned(session, HostHostname, (host_id, hostname_id), engagement_id=engagement_id)
    if link is not None:
        link.hidden = True  # sticky: a re-scan won't bring it back
        session.commit()
    return _hostnames_response(request, session, host, engagement_id=engagement_id)


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


def _invalid_ip_response(raw: str) -> JSONResponse:
    message = f'"{raw}" is not a valid IPv4 or IPv6 address.'
    return JSONResponse({"detail": message, "field_errors": {"ip": message}}, status_code=400)


def _duplicate_ip_response(norm: str) -> JSONResponse:
    return JSONResponse(
        {"detail": f'"{norm}" already belongs to another host, so this host was not changed.'},
        status_code=409,
    )


@scoped.post("/hosts")
def create_host(
    ip: str = Form(...), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    clean = ip.strip()
    if not clean:
        return RedirectResponse(f"/e/{engagement_id}" + "/", status_code=303)
    norm = _normalize_ip(clean)
    if norm is None:
        return _invalid_ip_response(clean)
    existing = session.exec(select(Host).where(Host.engagement_id == engagement_id).where(Host.ip == norm)).first()
    if existing is not None:
        return RedirectResponse(f"/e/{engagement_id}" + f"/hosts/{existing.id}", status_code=303)
    now = datetime.now(UTC)
    host = Host(ip=norm, first_seen=now, last_seen=now, engagement_id=engagement_id)
    session.add(host)
    session.commit()
    session.refresh(host)
    return RedirectResponse(f"/e/{engagement_id}" + f"/hosts/{host.id}", status_code=303)


@scoped.post("/hosts/{host_id}/edit")
def edit_host(
    host_id: int, ip: str = Form(...), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return RedirectResponse(f"/e/{engagement_id}" + "/", status_code=303)
    clean = ip.strip()
    if not clean:  # empty = leave the IP unchanged
        return RedirectResponse(f"/e/{engagement_id}" + f"/hosts/{host_id}", status_code=303)
    norm = _normalize_ip(clean)
    if norm is None:
        return _invalid_ip_response(clean)
    if norm != host.ip:
        dup = session.exec(select(Host).where(Host.engagement_id == engagement_id).where(Host.ip == norm)).first()
        if dup is not None:
            return _duplicate_ip_response(norm)
        host.ip = norm
        session.commit()
    return RedirectResponse(f"/e/{engagement_id}" + f"/hosts/{host_id}", status_code=303)


@scoped.post("/hosts/{host_id}/delete")
def delete_host(host_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> RedirectResponse:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return RedirectResponse(f"/e/{engagement_id}" + "/", status_code=303)
    # ON DELETE CASCADE (FKs on) sweeps services, observations, hostname links,
    # notes, annotations and credential links; credentials themselves survive.
    session.delete(host)
    session.commit()
    return RedirectResponse(f"/e/{engagement_id}" + "/", status_code=303)


def _clean(value: str) -> str | None:
    v = value.strip()
    return v or None


@scoped.post("/hosts/{host_id}/services", response_class=JSONResponse)
def add_service(
    request: Request,
    host_id: int,
    port: int = Form(...),
    proto: str = Form("tcp"),
    state: str = Form("open"),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    table: _ServiceTable = Depends(_service_table_form),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    svc = session.exec(
        select(Service).where(Service.engagement_id == engagement_id).where(
            Service.host_id == host_id, Service.port == port, Service.proto == proto.strip().lower()
        )
    ).first()
    if svc is None:
        svc = Service(host_id=host_id, port=port, proto=proto.strip().lower(), engagement_id=engagement_id)
        session.add(svc)
    svc.m_state = ObsState(state) if state else ObsState.open
    svc.m_service_name = _clean(service_name)
    svc.m_product = _clean(product)
    svc.m_version = _clean(version)
    session.commit()
    return _services_response(request, session, host, table, engagement_id=engagement_id)


@scoped.post("/services/{service_id}/edit", response_class=JSONResponse)
def edit_service(
    request: Request,
    service_id: int,
    state: str = Form(""),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    status: Status = Form(Status.new),
    tags: str = Form(""),
    table: _ServiceTable = Depends(_service_table_form),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    svc = queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
    if svc is None:
        return JSONResponse({"detail": "service not found"}, status_code=404)
    svc.m_state = ObsState(state) if state else None  # blank reverts to scan value
    svc.m_service_name = _clean(service_name)
    svc.m_product = _clean(product)
    svc.m_version = _clean(version)
    session.commit()
    # one Save persists both the scan overrides and the triage annotation
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    queries.upsert_annotation(session, status, tag_list, service_id=service_id, engagement_id=engagement_id)
    host = queries.get_owned(session, Host, svc.host_id, engagement_id=engagement_id)
    assert host is not None
    return _services_response(request, session, host, table, engagement_id=engagement_id)


@scoped.post("/services/{service_id}/delete", response_class=JSONResponse)
def delete_service(
    request: Request,
    service_id: int,
    table: _ServiceTable = Depends(_service_table_form),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    svc = queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
    if svc is None:
        return JSONResponse({"detail": "service not found"}, status_code=404)
    host = queries.get_owned(session, Host, svc.host_id, engagement_id=engagement_id)
    assert host is not None
    # hard delete: the service and everything tied to it. A later scan that sees
    # this port re-creates it fresh, as if it had never been deleted. The FK
    # cascade drops the annotation and credential links; observations key off
    # (host, port, proto) rather than service_id, so clear them by hand.
    for obs in session.exec(
        select(Observation).where(Observation.engagement_id == engagement_id).where(
            Observation.host_id == svc.host_id,
            Observation.port == svc.port,
            Observation.proto == svc.proto,
        )
    ).all():
        session.delete(obs)
    session.delete(svc)
    session.commit()
    return _services_response(request, session, host, table, engagement_id=engagement_id)


# --- credentials --------------------------------------------------------------

def _credential_context(session: Session, *, engagement_id: str) -> dict[str, object]:
    return {
        "credentials": queries.credential_views(session, engagement_id=engagement_id),
        "hosts": session.exec(select(Host).where(Host.engagement_id == engagement_id).order_by(Host.ip)).all(),
    }


def _credentials_response(request: Request, session: Session, *, engagement_id: str) -> Response:
    return page_response(request, _credential_context(session, engagement_id=engagement_id))


def _host_credentials_response(request: Request, session: Session, host_id: int, *, engagement_id: str) -> Response:
    return page_response(request, {
        "host": queries.get_owned(session, Host, host_id, engagement_id=engagement_id),
        "host_credentials": queries.credentials_for_host(session, host_id, engagement_id=engagement_id),
        "kinds": list(CredKind),
    })


@scoped.post("/credentials/{cred_id}/edit", response_class=JSONResponse)
def edit_credential(
    request: Request,
    cred_id: int,
    kind: str = Form("password"),
    username: str = Form(""),
    secret: str = Form(""),
    notes: str = Form(""),
    host_id: int | None = Form(None),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    cred = queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if host_id is not None and queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    try:
        cred.kind = CredKind(kind)
    except ValueError:
        cred.kind = CredKind.password
    cred.username = username.strip()
    cred.secret = secret.strip()
    cred.notes = notes.strip()
    session.commit()
    if host_id is not None:
        return _host_credentials_response(request, session, host_id, engagement_id=engagement_id)
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.get("/credentials", response_class=HTMLResponse)
def credentials_page(request: Request, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    return page_response(request, {
        **_credential_context(session, engagement_id=engagement_id),
        "kinds": list(CredKind),
    })


@scoped.post("/credentials", response_class=JSONResponse)
def create_credential(
    request: Request,
    kind: str = Form("password"),
    username: str = Form(""),
    secret: str = Form(""),
    notes: str = Form(""),
    host_ids: list[int] = Form([]),
    service_ids: list[int] = Form([]),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    user, sec = username.strip(), secret.strip()
    if not (user or sec):
        return JSONResponse({"detail": "a credential must carry at least a username or a secret"}, status_code=422)
    selected_hosts = set(host_ids)
    selected_services = set(service_ids)
    for host_id in selected_hosts:
        if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
            return JSONResponse({"detail": "host not found"}, status_code=422)
    for service_id in selected_services:
        service = queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
        if service is None:
            return JSONResponse({"detail": "service not found"}, status_code=422)
        if service.host_id not in selected_hosts:
            return JSONResponse({"detail": "service must belong to a selected host"}, status_code=422)
    try:
        k = CredKind(kind)
    except ValueError:
        k = CredKind.password
    credential = Credential(kind=k, username=user, secret=sec, notes=notes.strip(), engagement_id=engagement_id)
    session.add(credential)
    session.flush()
    assert credential.id is not None
    for host_id in selected_hosts:
        session.add(CredentialHost(credential_id=credential.id, host_id=host_id, engagement_id=engagement_id))
    for service_id in selected_services:
        session.add(CredentialService(credential_id=credential.id, service_id=service_id, engagement_id=engagement_id))
    session.commit()
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.post("/credentials/{cred_id}/delete", response_class=JSONResponse)
def delete_credential(
    request: Request,
    cred_id: int,
    host_id: int | None = Form(None),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    cred = queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if host_id is not None and queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    session.delete(cred)  # FK cascade drops its host/service link rows
    session.commit()
    if host_id is not None:
        return _host_credentials_response(request, session, host_id, engagement_id=engagement_id)
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.post("/credentials/{cred_id}/link/host", response_class=JSONResponse)
def link_cred_host(request: Request, cred_id: int, host_id: str = Form(""), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    hid = int(host_id) if host_id.strip().isdigit() else None
    if queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if hid is None:
        raise HTTPException(status_code=422, detail="Select a host, then choose Link host.")
    if queries.get_owned(session, Host, hid, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="Host is no longer available. Reload credentials and select another host.")
    if queries.get_owned(session, CredentialHost, (cred_id, hid), engagement_id=engagement_id) is None:
        session.add(CredentialHost(credential_id=cred_id, host_id=hid, engagement_id=engagement_id))  # ignore duplicate links
        session.commit()
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.post("/credentials/{cred_id}/unlink/host/{host_id}", response_class=JSONResponse)
def unlink_cred_host(request: Request, cred_id: int, host_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    if queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    service_links = session.exec(
        select(CredentialService).where(CredentialService.engagement_id == engagement_id)
        .join(Service, Service.id == CredentialService.service_id)  # type: ignore[arg-type]
        .where(CredentialService.credential_id == cred_id, Service.host_id == host_id)
    ).all()
    for service_link in service_links:
        session.delete(service_link)
    link = queries.get_owned(session, CredentialHost, (cred_id, host_id), engagement_id=engagement_id)
    if link is not None:
        session.delete(link)
    session.commit()
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.post("/credentials/{cred_id}/link/service", response_class=JSONResponse)
def link_cred_service(
    request: Request,
    cred_id: int,
    service_id: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    sid = int(service_id) if service_id.strip().isdigit() else None
    svc = queries.get_owned(session, Service, sid, engagement_id=engagement_id) if sid is not None else None
    if queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if svc is None:
        raise HTTPException(status_code=422 if sid is None else 404, detail="Select an available service, then choose Link service. Reload credentials if the service is no longer available.")
    # only services of a host already linked to this credential may be linked
    linked_host = queries.get_owned(
        session, CredentialHost, (cred_id, svc.host_id), engagement_id=engagement_id
    )
    if linked_host is not None and sid is not None and queries.get_owned(session, CredentialService, (cred_id, sid), engagement_id=engagement_id) is None:
        session.add(CredentialService(credential_id=cred_id, service_id=sid, engagement_id=engagement_id))
        session.commit()
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.post("/credentials/{cred_id}/unlink/service/{service_id}", response_class=JSONResponse)
def unlink_cred_service(request: Request, cred_id: int, service_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    if queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if queries.get_owned(session, Service, service_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="service not found")
    link = queries.get_owned(session, CredentialService, (cred_id, service_id), engagement_id=engagement_id)
    if link is not None:
        session.delete(link)
        session.commit()
    return _credentials_response(request, session, engagement_id=engagement_id)


@scoped.get("/scans", response_class=HTMLResponse)
def scans(request: Request, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    rows = session.exec(select(Scan).where(Scan.engagement_id == engagement_id).order_by(Scan.imported_at.desc())).all()  # type: ignore[attr-defined]
    return page_response(request, {"scans": rows, "tools": sorted(PARSERS)})


@scoped.post("/scans")
async def upload_scan(
    file: UploadFile, tool: str = Form("nmap"), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    data = await file.read()
    try:
        ingest_scan(session, data, file.filename or "upload", tool, engagement_id=engagement_id)
    except ScanParseError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return RedirectResponse(f"/e/{engagement_id}" + "/scans", status_code=303)


@scoped.get("/diff", response_class=HTMLResponse)
def diff(
    request: Request,
    a: int | None = None,
    b: int | None = None,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    all_scans = session.exec(select(Scan).where(Scan.engagement_id == engagement_id).order_by(Scan.imported_at.desc())).all()  # type: ignore[attr-defined]
    for scan_id in (a, b):
        if scan_id is not None and queries.get_owned(session, Scan, scan_id, engagement_id=engagement_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
    result = queries.diff_scans(session, a, b, engagement_id=engagement_id) if a and b else None
    return page_response(request, {"scans": all_scans, "result": result, "a": a, "b": b})


def _annotation_response(request: Request, session: Session, host_id: int, saved: bool = False, *, engagement_id: str) -> Response:
    if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    return page_response(request, {
        "host_id": host_id,
        "ann": queries.get_annotation(session, host_id=host_id, engagement_id=engagement_id),
        "statuses": list(Status),
        "saved": saved,
    })


@scoped.get("/annotation", response_class=HTMLResponse)
def annotation_get(
    request: Request,
    host_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return _annotation_response(request, session, host_id, engagement_id=engagement_id)


@scoped.post("/annotation", response_class=JSONResponse)
def annotation_post(
    request: Request,
    host_id: int = Form(...),
    status: Status = Form(Status.new),
    tags: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    queries.upsert_annotation(session, status, tag_list, host_id=host_id, engagement_id=engagement_id)
    return _annotation_response(request, session, host_id, saved=True, engagement_id=engagement_id)


# --- notes: any number of titled notes per host -------------------------------

def _notes_response(request: Request, session: Session, host_id: int, *, engagement_id: str) -> Response:
    return page_response(request, {
        "host_id": host_id,
        "notes": queries.notes_for(session, host_id, engagement_id=engagement_id),
    })


@scoped.post("/notes", response_class=JSONResponse)
def note_create(
    request: Request,
    host_id: int = Form(...),
    title: str = Form(""),
    body_md: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    clean_title = title.strip() or "Untitled"  # a note always has a title
    session.add(Note(host_id=host_id, title=clean_title, body_md=body_md, engagement_id=engagement_id))
    session.commit()
    return _notes_response(request, session, host_id, engagement_id=engagement_id)


@scoped.post("/notes/{note_id}/edit", response_class=JSONResponse)
def note_edit(
    request: Request,
    note_id: int,
    title: str = Form(""),
    body_md: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    note = queries.get_owned(session, Note, note_id, engagement_id=engagement_id)
    if note is None:
        return JSONResponse({"detail": "note not found"}, status_code=404)
    note.title = title.strip() or "Untitled"
    note.body_md = body_md
    note.updated_at = datetime.now(UTC)
    session.commit()
    return _notes_response(request, session, note.host_id, engagement_id=engagement_id)


@scoped.post("/notes/{note_id}/delete", response_class=JSONResponse)
def note_delete(request: Request, note_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    note = queries.get_owned(session, Note, note_id, engagement_id=engagement_id)
    if note is None:
        return JSONResponse({"detail": "note not found"}, status_code=404)
    host_id = note.host_id
    session.delete(note)
    session.commit()
    return _notes_response(request, session, host_id, engagement_id=engagement_id)


# --- operation log ------------------------------------------------------------

@dataclass(frozen=True)
class _OperationForm:
    started_at: datetime | None
    ended_at: datetime | None
    source: str
    destination: str
    tool: str
    user_context: str
    command: str
    output: str
    description: str
    comments: str
    tags: list[str]


def _parse_operation_datetime(raw: str, field: str) -> datetime | None:
    value = raw.strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field} date-time.") from exc


@dataclass(frozen=True)
class _OperationInput:
    """Bind raw form fields once; handlers choose when validation runs."""

    started_at: str = Form("")
    ended_at: str = Form("")
    source: str = Form("")
    destination: str = Form("")
    tool: str = Form("")
    user_context: str = Form("")
    command: str = Form("")
    output: str = Form("")
    description: str = Form("")
    comments: str = Form("")
    tags: str = Form("")

    def normalize(self) -> _OperationForm:
        parsed_start = _parse_operation_datetime(self.started_at, "started_at")
        parsed_end = _parse_operation_datetime(self.ended_at, "ended_at")
        clean_command = self.command.strip()
        if not clean_command:
            raise ValueError("Command is required.")
        if parsed_start is not None and parsed_end is not None and parsed_end < parsed_start:
            raise ValueError("ended_at must not be earlier than started_at.")
        return _OperationForm(
            started_at=parsed_start,
            ended_at=parsed_end,
            source=self.source.strip(),
            destination=self.destination.strip(),
            tool=self.tool.strip(),
            user_context=self.user_context.strip(),
            command=clean_command,
            output=self.output,
            description=self.description,
            comments=self.comments,
            tags=[tag.strip() for tag in self.tags.split(",") if tag.strip()],
        )


def _apply_operation_form(operation: OperationLog, values: _OperationForm) -> None:
    operation.started_at = values.started_at
    operation.ended_at = values.ended_at
    operation.source = values.source
    operation.destination = values.destination
    operation.tool = values.tool
    operation.user_context = values.user_context
    operation.command = values.command
    operation.output = values.output
    operation.description = values.description
    operation.comments = values.comments
    operation.tags = values.tags


def _operation_bad_request(message: str) -> JSONResponse:
    return JSONResponse({"detail": message}, status_code=400)


def _safe_attachment_path(stored_path: str | None, *, engagement_id: str) -> Path | None:
    if stored_path is None:
        return None
    root = engagement_attachments_dir(engagement_id).resolve()
    try:
        if Path(stored_path).is_absolute():
            return None
        path = (DATA_DIR / stored_path).resolve()
        path.relative_to(root)
    except (OSError, ValueError):
        return None
    return path


def _remove_operation_attachment(stored_path: str | None, *, engagement_id: str) -> None:
    path = _safe_attachment_path(stored_path, engagement_id=engagement_id)
    if path is not None:
        path.unlink(missing_ok=True)


def _save_operation_attachment(upload: UploadFile, *, engagement_id: str) -> tuple[str, str, str | None]:
    original_name = Path(upload.filename or "").name
    if not original_name:
        raise ValueError("Attachment filename is required.")
    directory = engagement_attachments_dir(engagement_id)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / uuid4().hex
    try:
        with destination.open("xb") as target:
            shutil.copyfileobj(upload.file, target)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return original_name, str(destination.relative_to(DATA_DIR)), upload.content_type


@scoped.get("/operations", response_class=HTMLResponse)
def operations_page(
    request: Request,
    q: str = "",
    page: int = 1,
    per: str = "25",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    normalized_per = (
        per
        if per == "all" or (per.isdigit() and int(per) in queries.PER_PAGE_OPTIONS)
        else "25"
    )
    matches = queries.operation_logs(session, q, engagement_id=engagement_id)
    page_rows, page, pages = queries.paginate(
        matches, page, queries.resolve_per_page(normalized_per)
    )
    context: dict[str, object] = {
        "operations": page_rows,
        "total": len(matches),
        "q": q,
        "page": page,
        "pages": pages,
        "per": normalized_per,
    }
    return page_response(request, context)


@scoped.post("/operations")
def create_operation(
    form: _OperationInput = Depends(_OperationInput),
    attachment: UploadFile | None = File(None),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    try:
        values = form.normalize()
    except ValueError as exc:
        return _operation_bad_request(str(exc))
    operation = OperationLog(command=values.command, engagement_id=engagement_id)
    _apply_operation_form(operation, values)
    new_path: str | None = None
    try:
        if attachment is not None and attachment.filename:
            name, new_path, media_type = _save_operation_attachment(attachment, engagement_id=engagement_id)
            operation.attachment_name = name
            operation.attachment_path = new_path
            operation.attachment_media_type = media_type
        session.add(operation)
        session.commit()
    except ValueError as exc:
        _remove_operation_attachment(new_path, engagement_id=engagement_id)
        return _operation_bad_request(str(exc))
    except Exception:
        session.rollback()
        _remove_operation_attachment(new_path, engagement_id=engagement_id)
        raise
    return RedirectResponse(f"/e/{engagement_id}" + "/operations", status_code=303)


@scoped.post("/operations/{operation_id}/edit")
def edit_operation(
    operation_id: int,
    form: _OperationInput = Depends(_OperationInput),
    remove_attachment: bool = Form(False),
    attachment: UploadFile | None = File(None),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    operation = queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        return JSONResponse({"detail": "operation not found"}, status_code=404)
    has_replacement = attachment is not None and bool(attachment.filename)
    if remove_attachment and has_replacement:
        return _operation_bad_request(
            "Cannot replace and remove an attachment in the same request."
        )
    try:
        values = form.normalize()
    except ValueError as exc:
        return _operation_bad_request(str(exc))

    old_path = operation.attachment_path
    new_path: str | None = None
    _apply_operation_form(operation, values)
    operation.updated_at = datetime.now(UTC)
    try:
        if has_replacement:
            assert attachment is not None
            name, new_path, media_type = _save_operation_attachment(attachment, engagement_id=engagement_id)
            operation.attachment_name = name
            operation.attachment_path = new_path
            operation.attachment_media_type = media_type
        elif remove_attachment:
            operation.attachment_name = None
            operation.attachment_path = None
            operation.attachment_media_type = None
        session.add(operation)
        session.commit()
    except ValueError as exc:
        session.rollback()
        _remove_operation_attachment(new_path, engagement_id=engagement_id)
        return _operation_bad_request(str(exc))
    except Exception:
        session.rollback()
        _remove_operation_attachment(new_path, engagement_id=engagement_id)
        raise

    if has_replacement or remove_attachment:
        _remove_operation_attachment(old_path, engagement_id=engagement_id)
    return RedirectResponse(f"/e/{engagement_id}" + "/operations", status_code=303)


@scoped.post("/operations/{operation_id}/delete")
def delete_operation(
    operation_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    operation = queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        return JSONResponse({"detail": "operation not found"}, status_code=404)
    old_path = operation.attachment_path
    session.delete(operation)
    session.commit()
    _remove_operation_attachment(old_path, engagement_id=engagement_id)
    return RedirectResponse(f"/e/{engagement_id}" + "/operations", status_code=303)


@scoped.get("/operations/{operation_id}/attachment")
def download_operation_attachment(
    operation_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    operation = queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None or not operation.attachment_name:
        return JSONResponse({"detail": "attachment not found"}, status_code=404)
    path = _safe_attachment_path(operation.attachment_path, engagement_id=engagement_id)
    if path is None or not path.is_file():
        return JSONResponse({"detail": "attachment not found"}, status_code=404)
    return FileResponse(
        path,
        filename=operation.attachment_name,
        media_type=operation.attachment_media_type or "application/octet-stream",
    )


app.include_router(scoped)
