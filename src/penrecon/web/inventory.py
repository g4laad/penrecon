"""Engagement-scoped inventory reads and manual host/service changes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import JSONResponse, Response
from sqlmodel import Session, select

from penrecon import commands
from penrecon.queries import annotations as annotation_queries
from penrecon.queries import credentials as credential_queries
from penrecon.queries import inventory as inventory_queries
from penrecon.queries import ownership as ownership_queries
from penrecon.queries import pagination as pagination_queries
from penrecon.db import get_session
from penrecon.inventory import (
    find_host_by_ip,
    hide_hostname,
    link_hostname,
    normalize_hostname,
    normalize_ip,
    same_ip,
)
from penrecon.models import CredKind, Host, ObsState, Service, Status
from penrecon.web.common import ErrorResponse, MutationResponse, invalid_command, mutation_response, owned_host, require_engagement
from penrecon.web.inventory_schemas import (
    HostDetailResponse,
    HostOptionsResponse,
    InventoryResponse,
    ServiceOptionsResponse,
    ServicesResponse,
    TimelineResponse,
)
from penrecon.web.serialization import encode_page, host_credential

router = APIRouter(
    tags=["Inventory"],
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)


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


def _query_integer(raw: str) -> int | None:
    clean = raw.strip()
    if len(clean) <= 10 and clean.isascii() and clean.isdecimal():
        return int(clean)
    return None


def _hosts_ctx(session: Session, table: _HostTable, *, engagement_id: str) -> dict[str, object]:
    q, port, tag, status, change = table.q, table.port, table.tag, table.status, table.change
    port_val = _query_integer(port)
    direction = table.dir if table.dir in ("asc", "desc") else pagination_queries.SORT_DEFAULT_DIR.get(table.sort, "asc")
    page_no = _query_integer(table.page) or 1
    per_limit = pagination_queries.resolve_per_page(table.per)
    fit = table.fit
    if len(fit) <= 2 and fit.isascii() and fit.isdecimal() and 1 <= int(fit) <= 50:
        per_limit = int(fit)
    result = inventory_queries.host_page(
        session, engagement_id=engagement_id, q=q, port=port_val, tag=tag,
        status=status, change=change, sort=table.sort, direction=direction,
        page=page_no, per_page=per_limit,
    )
    return {
        "q": q, "port": port, "tag": tag, "status": status, "change": change,
        "sort": table.sort, "direction": direction,
        "rows": result.rows, "total": result.total, "matched": result.matched,
        "page": result.page, "pages": result.pages,
    }


@router.get("/hosts", response_model=InventoryResponse)
def index(
    table: _HostTable = Depends(_HostTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    return JSONResponse(encode_page({
        **_hosts_ctx(session, table, engagement_id=engagement_id),
        "statuses": list(Status),
    }))


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
    session: Session, host: Host, table: _ServiceTable, *, engagement_id: str,
) -> dict[str, object]:
    """Filtered, sorted, server-paginated services; svc_total is the matched count."""
    assert host.id is not None
    direction = (
        table.dir if table.dir in ("asc", "desc")
        else pagination_queries.SERVICE_SORT_DEFAULT_DIR.get(table.sort, "asc")
    )
    page_no = _query_integer(table.page) or 1
    per_limit = pagination_queries.resolve_per_page(table.per)
    result = inventory_queries.service_page(
        session, host.id, engagement_id=engagement_id,
        port=table.f_port, state=table.f_state, service=table.f_service,
        status=table.f_status, sort=table.sort, direction=direction,
        page=page_no, per_page=per_limit,
    )
    return {
        "services": result.services, "svc_total": result.total,
        "page": result.page, "pages": result.pages, "sort": table.sort, "direction": direction,
        "per": "all" if per_limit is None else str(per_limit),
        "f_port": table.f_port, "f_state": table.f_state,
        "f_service": table.f_service, "f_status": table.f_status,
    }


@router.get("/hosts/{host_id}/services", response_model=ServicesResponse)
def services_data(
    host_id: int,
    table: _ServiceTable = Depends(_ServiceTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse(encode_page(_services_ctx(session, host, table, engagement_id=engagement_id)))


@router.get("/hosts/{host_id}/timeline", response_model=TimelineResponse)
def timeline_data(
    host_id: int,
    timeline_page: int = 1,
    timeline_unchanged: bool = False,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse(encode_page({
        "host_timeline": inventory_queries.host_timeline(
            session, host_id, engagement_id=engagement_id,
            page=timeline_page, show_unchanged=timeline_unchanged,
        ),
    }))


@router.get("/options/hosts", response_model=HostOptionsResponse)
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


@router.get("/options/hosts/{host_id}/services", response_model=ServiceOptionsResponse)
def service_options(
    host_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse({"services": [
        {"service_id": service.service_id, "port": service.port,
         "proto": service.proto, "service_name": service.service_name}
        for service in inventory_queries.resolved_services(session, host_id, engagement_id=engagement_id)
    ]})


@router.get("/hosts/{host_id}", response_model=HostDetailResponse)
def host_detail(
    host_id: int,
    table: _ServiceTable = Depends(_ServiceTable),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
    timeline_page: int = 1,
    timeline_unchanged: bool = False,
) -> Response:
    host = owned_host(session, host_id, engagement_id=engagement_id)
    return JSONResponse(encode_page({
        "host": host,
        "statuses": list(Status),
        "states": list(ObsState),
        "hostnames": inventory_queries.host_hostnames(session, host_id, engagement_id=engagement_id),
        "host_ann": annotation_queries.get_annotation(session, host_id=host_id, engagement_id=engagement_id),
        "host_notes": annotation_queries.notes_for(session, host_id, engagement_id=engagement_id),
        "host_credentials": [
            host_credential(credential)
            for credential in credential_queries.credentials_for_host(session, host_id, engagement_id=engagement_id)
        ],
        "host_timeline": inventory_queries.host_timeline(
            session, host_id, engagement_id=engagement_id,
            page=timeline_page, show_unchanged=timeline_unchanged,
        ),
        "kinds": list(CredKind),
        **_services_ctx(session, host, table, engagement_id=engagement_id),
    }))


@router.post("/hosts/{host_id}/hostnames", response_model=MutationResponse)
def add_hostname(
    host_id: int,
    name: str = Form(...),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    owned_host(session, host_id, engagement_id=engagement_id)
    try:
        clean = normalize_hostname(name) if name.strip() else ""
    except ValueError as exc:
        return JSONResponse({"detail": str(exc), "field_errors": {"name": str(exc)}}, status_code=400)
    if clean:
        link_hostname(session, host_id, clean, datetime.now(UTC), engagement_id=engagement_id)
        session.commit()
    return JSONResponse({"ok": True})


@router.delete("/hosts/{host_id}/hostnames/{hostname_id}", response_model=MutationResponse)
def delete_hostname(
    host_id: int,
    hostname_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    owned_host(session, host_id, engagement_id=engagement_id)
    if hide_hostname(session, host_id, hostname_id, engagement_id=engagement_id):
        session.commit()
    return JSONResponse({"ok": True})


def _invalid_ip_response(raw: str) -> JSONResponse:
    message = f'"{raw}" is not a valid IPv4 or IPv6 address.'
    return JSONResponse({"detail": message, "field_errors": {"ip": message}}, status_code=400)


def _duplicate_ip_response(norm: str) -> JSONResponse:
    return JSONResponse(
        {"detail": f'"{norm}" already belongs to another host, so this host was not changed.'},
        status_code=409,
    )


@router.post("/hosts", response_model=MutationResponse)
def create_host(
    ip: str = Form(...),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Create or select the canonical engagement/IP identity; blank is a no-op."""
    clean = ip.strip()
    if not clean:
        return mutation_response(f"/{engagement_id}/")
    try:
        norm = normalize_ip(clean)
    except ValueError:
        return _invalid_ip_response(clean)
    existing = find_host_by_ip(session, norm, engagement_id=engagement_id)
    if existing is not None:
        return mutation_response(f"/{engagement_id}/hosts/{existing.id}")
    now = datetime.now(UTC)
    host = Host(ip=norm, first_seen=now, last_seen=now, engagement_id=engagement_id)
    session.add(host)
    session.commit()
    session.refresh(host)
    return mutation_response(f"/{engagement_id}/hosts/{host.id}")


@router.patch("/hosts/{host_id}", response_model=MutationResponse)
def edit_host(
    host_id: int,
    ip: str = Form(...),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Rename an owned identity without merging hosts; blank keeps its address."""
    host = owned_host(session, host_id, engagement_id=engagement_id)
    clean = ip.strip()
    if not clean:
        return mutation_response(f"/{engagement_id}/hosts/{host_id}")
    try:
        norm = normalize_ip(clean)
    except ValueError:
        return _invalid_ip_response(clean)
    if not same_ip(norm, host.ip):
        duplicate = find_host_by_ip(session, norm, engagement_id=engagement_id, excluding=host_id)
        if duplicate is not None:
            return _duplicate_ip_response(norm)
        host.ip = norm
        session.commit()
    return mutation_response(f"/{engagement_id}/hosts/{host_id}")


@router.delete("/hosts/{host_id}", response_model=MutationResponse)
def delete_host(
    host_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    host = owned_host(session, host_id, engagement_id=engagement_id)
    # Cascades remove dependent evidence and links; credentials themselves survive.
    session.delete(host)
    session.commit()
    return mutation_response(f"/{engagement_id}/")


@router.post("/hosts/{host_id}/services", response_model=MutationResponse)
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
    owned_host(session, host_id, engagement_id=engagement_id)
    try:
        identity = commands.ServiceIdentity.parse(port, proto)
        values = commands.ServiceOverrides.parse(state, service_name, product, version, creating=True)
    except commands.InvalidCommand as exc:
        return invalid_command(exc)
    service = session.exec(
        select(Service).where(Service.engagement_id == engagement_id).where(
            Service.host_id == host_id, Service.port == identity.port, Service.proto == identity.proto
        )
    ).first()
    observation = inventory_queries.latest_observations(session, host_id, engagement_id=engagement_id).get(
        (identity.port, identity.proto)
    )
    creating = service is None
    if service is None:
        service = Service(host_id=host_id, port=identity.port, proto=identity.proto, engagement_id=engagement_id)
    commands.override_service(session, service, values, observation, creating=creating)
    session.commit()
    return JSONResponse({"ok": True})


@router.put("/services/{service_id}", response_model=MutationResponse)
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
    """Replace editable overrides and triage; blank overrides restore scan values."""
    service = ownership_queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    try:
        values = commands.ServiceOverrides.parse(state, service_name, product, version)
    except commands.InvalidCommand as exc:
        return invalid_command(exc)
    observation = inventory_queries.latest_observations(session, service.host_id, engagement_id=engagement_id).get(
        (service.port, service.proto)
    )
    commands.override_service(session, service, values, observation)
    # Saving persists both scan overrides and triage annotations together.
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
    annotation_queries.upsert_annotation(session, status, tag_list, service_id=service_id, engagement_id=engagement_id)
    return JSONResponse({"ok": True})


@router.delete("/services/{service_id}", response_model=MutationResponse)
def delete_service(
    service_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    service = ownership_queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
    if service is None:
        raise HTTPException(status_code=404, detail="service not found")
    observation = inventory_queries.latest_observations(session, service.host_id, engagement_id=engagement_id).get(
        (service.port, service.proto)
    )
    commands.remove_service(session, service, observation)
    session.commit()
    return JSONResponse({"ok": True})
