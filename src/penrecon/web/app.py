"""FastAPI routes and the React application page-data boundary."""

from __future__ import annotations

import csv
import io
import json
import logging
import shutil
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from enum import StrEnum
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlmodel import Session, col, select

from penrecon import commands, queries
from penrecon.db import DATA_DIR, engagement_attachments_dir, get_session, init_db
from penrecon.ingest import ScanParseError, ingest_scan
from penrecon.inventory import find_host_by_ip, hide_hostname, link_hostname, normalize_hostname, normalize_ip, same_ip
from penrecon.models import (
    CredKind,
    Credential,
    CredentialService,
    Engagement,
    Host,
    Note,
    ObsState,
    OperationLog,
    Scan,
    Service,
    Status,
)
from penrecon.parsers import PARSERS
from penrecon.web.serialization import encode_page, host_credential

_HERE = Path(__file__).parent


def _bootstrap(request: Request, session: Session) -> dict[str, object]:
    engagement = getattr(request.state, "engagement", None)
    if engagement is None:
        return {"engagement": None, "engagements": []}
    return {
        "engagement": {"id": engagement.id, "name": engagement.name},
        "engagements": [
            {"id": engagement_id, "name": name}
            for engagement_id, name in session.exec(
                select(Engagement.id, Engagement.name).order_by(col(Engagement.created_at).desc())
            ).all()
        ],
    }


def page_response(request: Request, session: Session, context: dict[str, object]) -> Response:
    """Return page context as JSON; only HTML also loads the navigation shell."""
    headers = {"Vary": "Accept"}
    if "application/json" in request.headers.get("accept", "").lower():
        return JSONResponse(encode_page(context), headers=headers)
    data = encode_page({**_bootstrap(request, session), **context})
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


def _mutation_response(request: Request, redirect_to: str) -> Response:
    """Acknowledge JSON mutations without following a document redirect."""
    headers = {"Vary": "Accept"}
    if "application/json" in request.headers.get("accept", "").lower():
        return JSONResponse({"ok": True, "redirect_to": redirect_to}, headers=headers)
    return RedirectResponse(redirect_to, status_code=303, headers=headers)


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
    return engagement_id


scoped = APIRouter(prefix="/e/{engagement_id}")


@scoped.get("/bootstrap")
def bootstrap(
    request: Request,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return JSONResponse(_bootstrap(request, session))


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
    engagements = session.exec(
        select(Engagement).order_by(
            order.desc() if direction == "desc" else order.asc(),
            col(Engagement.id).asc(),
        )
    ).all()
    return page_response(request, session, {"catalog": engagements, "sort": sort, "direction": direction})


@app.post("/engagements")
def create_engagement(
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
) -> Response:
    """Create a named workspace; no status/archive lifecycle is implied."""
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
    return _mutation_response(request, f"/e/{engagement.id}/")


@app.post("/engagements/{engagement_id}/edit")
def edit_engagement(
    engagement_id: str,
    name: str = Form(""),
    description: str = Form(""),
    session: Session = Depends(get_session),
) -> Response:
    """Replace editable metadata, retaining workspace identity and evidence."""
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


@dataclass(frozen=True)
class _HostTable:
    q: str = ""
    port: str = ""
    tag: str = ""
    status: str = ""
    change: str = ""
    sort: str = "change"
    dir: str = ""
    page: str = "1"
    per: str = ""
    fit: str = ""


def _hosts_ctx(
    session: Session, table: _HostTable, *, engagement_id: str, load_rows: bool = True,
) -> dict[str, object]:
    q, port, tag, status, change = table.q, table.port, table.tag, table.status, table.change
    sort = table.sort
    port_val = int(port) if port.strip().isdigit() else None
    direction = table.dir if table.dir in ("asc", "desc") else queries.SORT_DEFAULT_DIR.get(sort, "asc")
    page_no = int(table.page) if table.page.strip().isdigit() else 1
    per_limit = queries.resolve_per_page(table.per)
    fit = table.fit
    if len(fit) <= 2 and fit.isascii() and fit.isdecimal() and 1 <= int(fit) <= 50:
        per_limit = int(fit)
    state: dict[str, object] = {
        "q": q, "port": port, "tag": tag, "status": status, "change": change,
        "sort": sort, "direction": direction,
    }
    if not load_rows:
        return {**state, "page": max(1, page_no)}
    all_rows = queries.host_rows(session, engagement_id=engagement_id)
    rows = queries.filter_hosts(
        all_rows, q=q, port=port_val, tag=tag, status=status, change=change
    )
    rows = queries.sort_hosts(rows, sort, direction)
    matched = len(rows)
    page_rows, page_no, pages = queries.paginate(rows, page_no, per_limit)
    return {**state, "rows": page_rows, "total": len(all_rows), "matched": matched,
            "page": page_no, "pages": pages}


@scoped.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    table: _HostTable = Depends(_HostTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return page_response(request, session, {
        **_hosts_ctx(session, table, engagement_id=engagement_id,
                     load_rows="application/json" in request.headers.get("accept", "").lower()),
        "statuses": list(Status),
    })


@scoped.get("/data/hosts")
def hosts_data(
    table: _HostTable = Depends(_HostTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return JSONResponse(encode_page(_hosts_ctx(session, table, engagement_id=engagement_id)))


@scoped.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "", engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    return page_response(request, session, {"q": q.strip(), "results": queries.search(session, q, engagement_id=engagement_id)})


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
    """Query state for the host detail service table."""

    sort: str = "port"
    dir: str = ""
    page: str = "1"
    f_port: str = ""
    f_state: str = ""
    f_service: str = ""
    f_status: str = ""
    per: str = ""


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
    return {"services": page_services, "svc_total": total,
            "page": page_no, "pages": pages, "sort": table.sort, "direction": direction,
            "per": "all" if per_limit is None else str(per_limit),
            "f_port": table.f_port, "f_state": table.f_state,
            "f_service": table.f_service, "f_status": table.f_status}


def _owned_host(session: Session, host_id: int, *, engagement_id: str) -> Host:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    return host


@scoped.get("/data/hosts/{host_id}/services")
def services_data(
    host_id: int,
    table: _ServiceTable = Depends(_ServiceTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = _owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse(encode_page(_services_ctx(session, host, table, engagement_id=engagement_id)))


@scoped.get("/data/hosts/{host_id}/timeline")
def timeline_data(
    host_id: int,
    timeline_page: int = 1,
    timeline_unchanged: bool = False,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    _owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse(encode_page({
        "host_timeline": queries.host_timeline(
            session, host_id, engagement_id=engagement_id,
            page=timeline_page, show_unchanged=timeline_unchanged,
        ),
    }))


@scoped.get("/options/hosts")
def host_options(
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return JSONResponse({"hosts": [
        {"id": host_id, "ip": ip}
        for host_id, ip in session.exec(
            select(Host.id, Host.ip).where(Host.engagement_id == engagement_id).order_by(Host.ip)
        ).all()
    ]})


@scoped.get("/options/hosts/{host_id}/services")
def service_options(
    host_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    _owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse({"services": [
        {"service_id": service.service_id, "port": service.port,
         "proto": service.proto, "service_name": service.service_name}
        for service in queries.resolved_services(session, host_id, engagement_id=engagement_id)
    ]})

@scoped.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_detail(
    request: Request,
    host_id: int,
    table: _ServiceTable = Depends(_ServiceTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
    timeline_page: int = 1,
    timeline_unchanged: bool = False,
) -> Response:
    host = _owned_host(session, host_id, engagement_id=engagement_id)
    svc_ctx = _services_ctx(session, host, table, engagement_id=engagement_id)
    return page_response(request, session, {
        "host": host,
        "statuses": list(Status),
        "states": list(ObsState),
        "hostnames": queries.host_hostnames(session, host_id, engagement_id=engagement_id),
        "host_ann": queries.get_annotation(session, host_id=host_id, engagement_id=engagement_id),
        "host_notes": queries.notes_for(session, host_id, engagement_id=engagement_id),
        "host_credentials": [
            host_credential(credential, host_id)
            for credential in queries.credentials_for_host(session, host_id, engagement_id=engagement_id)
        ],
        "host_timeline": queries.host_timeline(
            session, host_id, engagement_id=engagement_id,
            page=timeline_page, show_unchanged=timeline_unchanged,
        ),
        "kinds": list(CredKind),
        **svc_ctx,
    })


@scoped.post("/hosts/{host_id}/hostnames", response_class=JSONResponse)
def add_hostname(
    host_id: int,
    name: str = Form(...),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    try:
        clean = normalize_hostname(name) if name.strip() else ""
    except ValueError as exc:
        return JSONResponse({"detail": str(exc), "field_errors": {"name": str(exc)}}, status_code=400)
    if clean:
        link_hostname(session, host_id, clean, datetime.now(UTC), engagement_id=engagement_id)
        session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/hosts/{host_id}/hostnames/{hostname_id}/delete", response_class=JSONResponse)
def delete_hostname(host_id: int, hostname_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    if hide_hostname(session, host_id, hostname_id, engagement_id=engagement_id):
        session.commit()
    return JSONResponse({"ok": True})


# --- manual host + service CRUD -----------------------------------------------



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
    request: Request,
    ip: str = Form(...), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    """Create or select the canonical engagement/IP identity; blank is a no-op."""
    clean = ip.strip()
    if not clean:
        return _mutation_response(request, f"/e/{engagement_id}/")
    try:
        norm = normalize_ip(clean)
    except ValueError:
        return _invalid_ip_response(clean)
    existing = find_host_by_ip(session, norm, engagement_id=engagement_id)
    if existing is not None:
        return _mutation_response(request, f"/e/{engagement_id}/hosts/{existing.id}")
    now = datetime.now(UTC)
    host = Host(ip=norm, first_seen=now, last_seen=now, engagement_id=engagement_id)
    session.add(host)
    session.commit()
    session.refresh(host)
    return _mutation_response(request, f"/e/{engagement_id}/hosts/{host.id}")


@scoped.post("/hosts/{host_id}/edit")
def edit_host(
    request: Request,
    host_id: int, ip: str = Form(...), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    """Rename an owned identity without merging hosts; blank keeps its address."""
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return _mutation_response(request, f"/e/{engagement_id}/")
    clean = ip.strip()
    if not clean:  # empty = leave the IP unchanged
        return _mutation_response(request, f"/e/{engagement_id}/hosts/{host_id}")
    try:
        norm = normalize_ip(clean)
    except ValueError:
        return _invalid_ip_response(clean)
    if not same_ip(norm, host.ip):
        dup = find_host_by_ip(session, norm, engagement_id=engagement_id, excluding=host_id)
        if dup is not None:
            return _duplicate_ip_response(norm)
        host.ip = norm
        session.commit()
    return _mutation_response(request, f"/e/{engagement_id}/hosts/{host_id}")


@scoped.post("/hosts/{host_id}/delete")
def delete_host(request: Request, host_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return _mutation_response(request, f"/e/{engagement_id}/")
    # ON DELETE CASCADE (FKs on) sweeps services, observations, hostname links,
    # notes, annotations and credential links; credentials themselves survive.
    session.delete(host)
    session.commit()
    return _mutation_response(request, f"/e/{engagement_id}/")


def _invalid_command(exc: commands.InvalidCommand, *, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        {"detail": str(exc), "field_errors": {exc.field: str(exc)}},
        status_code=status_code,
    )


@scoped.post("/hosts/{host_id}/services", response_class=JSONResponse)
def add_service(
    host_id: int,
    port: int = Form(...),
    proto: str = Form("tcp"),
    state: str = Form("open"),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        return JSONResponse({"detail": "host not found"}, status_code=404)
    try:
        identity = commands.ServiceIdentity.parse(port, proto)
        values = commands.ServiceOverrides.parse(state, service_name, product, version, creating=True)
    except commands.InvalidCommand as exc:
        return _invalid_command(exc)
    svc = session.exec(
        select(Service).where(Service.engagement_id == engagement_id).where(
            Service.host_id == host_id, Service.port == identity.port, Service.proto == identity.proto
        )
    ).first()
    observation = queries.latest_observations(session, host_id, engagement_id=engagement_id).get(
        (identity.port, identity.proto)
    )
    creating = svc is None
    if svc is None:
        svc = Service(host_id=host_id, port=identity.port, proto=identity.proto, engagement_id=engagement_id)
    commands.override_service(session, svc, values, observation, creating=creating)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/services/{service_id}/edit", response_class=JSONResponse)
def edit_service(
    service_id: int,
    state: str = Form(""),
    service_name: str = Form(""),
    product: str = Form(""),
    version: str = Form(""),
    status: Status = Form(Status.new),
    tags: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    svc = queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
    if svc is None:
        return JSONResponse({"detail": "service not found"}, status_code=404)
    try:
        values = commands.ServiceOverrides.parse(state, service_name, product, version)
    except commands.InvalidCommand as exc:
        return _invalid_command(exc)
    observation = queries.latest_observations(session, svc.host_id, engagement_id=engagement_id).get(
        (svc.port, svc.proto)
    )
    commands.override_service(session, svc, values, observation)
    # one Save persists both the scan overrides and the triage annotation
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    queries.upsert_annotation(session, status, tag_list, service_id=service_id, engagement_id=engagement_id)
    host = queries.get_owned(session, Host, svc.host_id, engagement_id=engagement_id)
    assert host is not None
    return JSONResponse({"ok": True})


@scoped.post("/services/{service_id}/delete", response_class=JSONResponse)
def delete_service(
    service_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    svc = queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
    if svc is None:
        return JSONResponse({"detail": "service not found"}, status_code=404)
    host = queries.get_owned(session, Host, svc.host_id, engagement_id=engagement_id)
    assert host is not None
    observation = queries.latest_observations(session, svc.host_id, engagement_id=engagement_id).get(
        (svc.port, svc.proto)
    )
    commands.remove_service(session, svc, observation)
    session.commit()
    return JSONResponse({"ok": True})


# --- credentials --------------------------------------------------------------



@scoped.post("/credentials/{cred_id}/edit", response_class=JSONResponse)
def edit_credential(
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
        values = commands.CredentialValues.parse(kind, username, secret, notes)
    except commands.InvalidCommand as exc:
        return _invalid_command(exc, status_code=422)
    values.apply(cred)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.get("/credentials", response_class=HTMLResponse)
def credentials_page(
    request: Request,
    filter: str = "",
    kind: str = "",
    scope: str = "",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    credentials, total = queries.credential_summaries(
        session, filter, kind, scope, engagement_id=engagement_id,
    )
    return page_response(request, session, {
        "credentials": credentials, "total": total, "kinds": list(CredKind),
        "q": filter, "kind": kind, "scope": scope,
    })


@scoped.get("/credentials/{cred_id}")
def credential_detail(
    cred_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    credential = queries.credential_view(session, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(
            status_code=404, detail="credential not found", headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        encode_page({"credential": credential}), headers={"Cache-Control": "no-store"},
    )


@scoped.post("/credentials", response_class=JSONResponse)
def create_credential(
    kind: str = Form("password"),
    username: str = Form(""),
    secret: str = Form(""),
    notes: str = Form(""),
    host_ids: list[int] = Form([]),
    service_ids: list[int] = Form([]),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    try:
        values = commands.CredentialValues.parse(kind, username, secret, notes)
    except commands.InvalidCommand as exc:
        return _invalid_command(exc, status_code=422)
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
    credential = Credential(engagement_id=engagement_id)
    values.apply(credential)
    session.add(credential)
    session.flush()
    assert credential.id is not None
    for host_id in selected_hosts:
        host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
        assert host is not None
        commands.link_credential_host(session, credential, host)
    session.flush()  # service guards must see every staged host association
    for service_id in selected_services:
        service = queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
        assert service is not None
        commands.link_credential_service(session, credential, service)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/credentials/{cred_id}/delete", response_class=JSONResponse)
def delete_credential(
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
    return JSONResponse({"ok": True})


@scoped.post("/credentials/{cred_id}/link/host", response_class=JSONResponse)
def link_cred_host(cred_id: int, host_id: str = Form(""), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    hid = int(host_id) if host_id.strip().isdigit() else None
    credential = queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if hid is None:
        raise HTTPException(status_code=422, detail="Select a host, then choose Link host.")
    host = queries.get_owned(session, Host, hid, engagement_id=engagement_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Host is no longer available. Reload credentials and select another host.")
    commands.link_credential_host(session, credential, host)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/credentials/{cred_id}/unlink/host/{host_id}", response_class=JSONResponse)
def unlink_cred_host(cred_id: int, host_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    credential = queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="credential not found")
    host = queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    commands.unlink_credential_host(session, credential, host)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/credentials/{cred_id}/link/service", response_class=JSONResponse)
def link_cred_service(
    cred_id: int,
    service_id: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    sid = int(service_id) if service_id.strip().isdigit() else None
    svc = queries.get_owned(session, Service, sid, engagement_id=engagement_id) if sid is not None else None
    credential = queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if svc is None:
        raise HTTPException(status_code=422 if sid is None else 404, detail="Select an available service, then choose Link service. Reload credentials if the service is no longer available.")
    try:
        commands.link_credential_service(session, credential, svc)
    except commands.InvalidCommand as exc:
        return _invalid_command(exc, status_code=422)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/credentials/{cred_id}/unlink/service/{service_id}", response_class=JSONResponse)
def unlink_cred_service(cred_id: int, service_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    if queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if queries.get_owned(session, Service, service_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="service not found")
    link = queries.get_owned(session, CredentialService, (cred_id, service_id), engagement_id=engagement_id)
    if link is not None:
        session.delete(link)
        session.commit()
    return JSONResponse({"ok": True})


@scoped.get("/scans", response_class=HTMLResponse)
def scans(request: Request, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    rows = session.exec(select(Scan).where(Scan.engagement_id == engagement_id).order_by(Scan.imported_at.desc())).all()  # type: ignore[attr-defined]
    return page_response(request, session, {"scans": rows, "tools": sorted(PARSERS)})


@scoped.post("/scans")
async def upload_scan(
    request: Request,
    file: UploadFile, tool: str = Form("nmap"), engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    data = await file.read()
    try:
        ingest_scan(session, data, file.filename or "upload", tool, engagement_id=engagement_id)
    except ScanParseError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return _mutation_response(request, f"/e/{engagement_id}/scans")


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
    return page_response(request, session, {"scans": all_scans, "result": result, "a": a, "b": b})


def _annotation_response(request: Request, session: Session, host_id: int, *, engagement_id: str) -> Response:
    if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    return page_response(request, session, {
        "host_id": host_id,
        "ann": queries.get_annotation(session, host_id=host_id, engagement_id=engagement_id),
        "statuses": list(Status),
        "saved": False,
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
    return JSONResponse({"ok": True})


# --- notes: any number of titled notes per host -------------------------------

@scoped.post("/notes", response_class=JSONResponse)
def note_create(
    host_id: int = Form(...),
    title: str = Form(""),
    body_md: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Create a titled host note, preserving Markdown verbatim (no publish state)."""
    if queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    clean_title = title.strip() or "Untitled"  # a note always has a title
    session.add(Note(host_id=host_id, title=clean_title, body_md=body_md, engagement_id=engagement_id))
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/notes/{note_id}/edit", response_class=JSONResponse)
def note_edit(
    note_id: int,
    title: str = Form(""),
    body_md: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Replace note content and advance edit time; blank title becomes Untitled."""
    note = queries.get_owned(session, Note, note_id, engagement_id=engagement_id)
    if note is None:
        return JSONResponse({"detail": "note not found"}, status_code=404)
    note.title = title.strip() or "Untitled"
    note.body_md = body_md
    note.updated_at = datetime.now(UTC)
    session.commit()
    return JSONResponse({"ok": True})


@scoped.post("/notes/{note_id}/delete", response_class=JSONResponse)
def note_delete(note_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)) -> Response:
    note = queries.get_owned(session, Note, note_id, engagement_id=engagement_id)
    if note is None:
        return JSONResponse({"detail": "note not found"}, status_code=404)
    session.delete(note)
    session.commit()
    return JSONResponse({"ok": True})


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
        if parsed_start is not None and parsed_end is not None and (
            (parsed_start.utcoffset() is None) != (parsed_end.utcoffset() is None)
        ):
            raise ValueError("Use the same timezone convention for started_at and ended_at.")
        if parsed_start is not None and parsed_end is not None and parsed_end < parsed_start:
            raise ValueError("ended_at must not be earlier than started_at.")
        return _OperationForm(
            # SQLite stores naive datetimes: aware inputs must first become UTC
            # rather than silently losing their offset. Naive operator-local
            # times remain naive; mixing the conventions is rejected above.
            started_at=parsed_start.astimezone(UTC).replace(tzinfo=None) if parsed_start is not None and parsed_start.utcoffset() is not None else parsed_start,
            ended_at=parsed_end.astimezone(UTC).replace(tzinfo=None) if parsed_end is not None and parsed_end.utcoffset() is not None else parsed_end,
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
    except Exception as exc:
        try:
            destination.unlink(missing_ok=True)
        except OSError as cleanup:
            exc.add_note(f"Partial attachment cleanup pending: {cleanup}")
        raise
    return original_name, str(destination.relative_to(DATA_DIR)), upload.content_type


class _AttachmentAction(StrEnum):
    keep = "keep"
    replacement = "replace"
    remove = "remove"


@dataclass
class _AttachmentChange:
    """One guarded file transition; old bytes survive until metadata commits."""

    action: _AttachmentAction
    upload: UploadFile | None
    old_path: str | None
    new_path: str | None = None

    @classmethod
    def choose(cls, operation: OperationLog, upload: UploadFile | None, remove: bool = False) -> _AttachmentChange:
        replacing = upload is not None and bool(upload.filename)
        if replacing and remove:
            raise ValueError("Cannot replace and remove an attachment in the same request.")
        return cls(
            _AttachmentAction.replacement if replacing else _AttachmentAction.remove if remove else _AttachmentAction.keep,
            upload, operation.attachment_path,
        )

    def stage(self, operation: OperationLog) -> None:
        if self.action == _AttachmentAction.replacement:
            assert self.upload is not None
            name, self.new_path, media_type = _save_operation_attachment(self.upload, engagement_id=operation.engagement_id)
            operation.attachment_name = name
            operation.attachment_path = self.new_path
            operation.attachment_media_type = media_type
        elif self.action == _AttachmentAction.remove:
            operation.attachment_name = None
            operation.attachment_path = None
            operation.attachment_media_type = None

    def compensate(self, engagement_id: str, failure: Exception) -> None:
        try:
            _remove_operation_attachment(self.new_path, engagement_id=engagement_id)
        except OSError as cleanup:
            failure.add_note(f"New attachment cleanup pending after rollback: {cleanup}")
            logging.getLogger(__name__).warning("Rolled-back attachment cleanup pending: %s", cleanup)

    def finish(self, engagement_id: str) -> bool:
        if self.action == _AttachmentAction.keep:
            return False
        try:
            _remove_operation_attachment(self.old_path, engagement_id=engagement_id)
        except OSError:
            logging.getLogger(__name__).warning("Committed operation attachment cleanup pending: %s", self.old_path, exc_info=True)
            return True
        return False


def _commit_operation(
    session: Session, operation: OperationLog, change: _AttachmentChange,
    values: _OperationForm | None,
) -> bool:
    """Commit edit/create/delete, compensate only uncommitted new files.

    Returns whether obsolete-file cleanup remains after a successful commit.
    No exception from that cleanup may imply that the database mutation failed.
    """
    engagement_id = operation.engagement_id
    try:
        if values is None:
            session.delete(operation)
        else:
            _apply_operation_form(operation, values)
            operation.updated_at = datetime.now(UTC)
            change.stage(operation)
            session.add(operation)
        session.commit()
    except Exception as exc:
        try:
            session.rollback()
        except Exception as rollback:
            exc.add_note(f"Operation rollback failed: {rollback}")
        change.compensate(engagement_id, exc)
        raise
    return change.finish(engagement_id)


def _operation_committed_response(request: Request, engagement_id: str, cleanup_pending: bool, *, deleted: bool = False) -> Response:
    destination = f"/e/{engagement_id}/operations"
    if cleanup_pending:
        return JSONResponse({
            "ok": True, "committed": True, "cleanup_pending": True,
            "detail": f"Operation {'deleted' if deleted else 'saved'}; obsolete attachment cleanup could not finish.",
            "redirect_to": destination,
        })
    return _mutation_response(request, destination)


def _operations_ctx(
    session: Session, q: str, page: int, per: str, *, engagement_id: str,
) -> dict[str, object]:
    normalized_per = (
        per
        if per == "all" or (per.isdigit() and int(per) in queries.PER_PAGE_OPTIONS)
        else "25"
    )
    matches = queries.operation_logs(session, q, engagement_id=engagement_id)
    page_rows, page, pages = queries.paginate(
        matches, page, queries.resolve_per_page(normalized_per)
    )
    return {
        "operations": page_rows,
        "total": len(matches),
        "q": q,
        "page": page,
        "pages": pages,
        "per": normalized_per,
    }


@scoped.get("/operations", response_class=HTMLResponse)
def operations_page(
    request: Request,
    q: str = "",
    page: int = 1,
    per: str = "25",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return page_response(
        request, session, _operations_ctx(session, q, page, per, engagement_id=engagement_id),
    )


@scoped.get("/data/operations")
def operations_data(
    q: str = "",
    page: int = 1,
    per: str = "25",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return JSONResponse(encode_page(_operations_ctx(session, q, page, per, engagement_id=engagement_id)))


@scoped.get("/operations/{operation_id}")
def operation_detail(
    operation_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    operation = queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        raise HTTPException(
            status_code=404, detail="operation not found", headers={"Cache-Control": "no-store"},
        )
    return JSONResponse(
        encode_page({"operation": operation}), headers={"Cache-Control": "no-store"},
    )


@scoped.post("/operations")
def create_operation(
    request: Request,
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
    change = _AttachmentChange.choose(operation, attachment)
    try:
        cleanup_pending = _commit_operation(session, operation, change, values)
    except ValueError as exc:
        return _operation_bad_request(str(exc))
    return _operation_committed_response(request, engagement_id, cleanup_pending)


@scoped.post("/operations/{operation_id}/edit")
def edit_operation(
    request: Request,
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
    try:
        change = _AttachmentChange.choose(operation, attachment, remove_attachment)
        values = form.normalize()
    except ValueError as exc:
        return _operation_bad_request(str(exc))
    try:
        cleanup_pending = _commit_operation(session, operation, change, values)
    except ValueError as exc:
        return _operation_bad_request(str(exc))
    return _operation_committed_response(request, engagement_id, cleanup_pending)


@scoped.post("/operations/{operation_id}/delete")
def delete_operation(
    request: Request,
    operation_id: int, engagement_id: str = Depends(require_engagement), session: Session = Depends(get_session)
) -> Response:
    operation = queries.get_owned(session, OperationLog, operation_id, engagement_id=engagement_id)
    if operation is None:
        return JSONResponse({"detail": "operation not found"}, status_code=404)
    change = _AttachmentChange.choose(operation, None, remove=True)
    cleanup_pending = _commit_operation(session, operation, change, None)
    return _operation_committed_response(request, engagement_id, cleanup_pending, deleted=True)


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
