"""Credential identities, secret detail, and owned host/service associations."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlmodel import Session, select

from penrecon import commands
from penrecon.queries import credentials as credential_queries
from penrecon.queries import ownership as ownership_queries
from penrecon.queries import pagination as pagination_queries
from penrecon.db import get_session
from penrecon.models import CredKind, Credential, CredentialService, Host, Service
from penrecon.web.common import ErrorResponse, MutationResponse, invalid_command, require_engagement
from penrecon.web.serialization import encode_page


class CredentialSummaryResponse(BaseModel):
    id: int
    kind: CredKind
    username: str
    notes_preview: str
    host_count: int
    service_count: int


class CredentialHostResponse(BaseModel):
    host_id: int
    ip: str


class CredentialServiceResponse(BaseModel):
    service_id: int
    host_id: int
    ip: str
    port: int
    proto: str
    name: str | None


class CredentialResponse(BaseModel):
    id: int
    kind: CredKind
    username: str
    secret: str
    notes: str
    created_at: str
    hosts: list[CredentialHostResponse]
    services: list[CredentialServiceResponse]


class CredentialsPageResponse(BaseModel):
    credentials: list[CredentialSummaryResponse]
    total: int
    matched: int
    page: int
    pages: int
    per: str
    kinds: list[CredKind]
    q: str
    kind: str
    scope: str


class CredentialDetailResponse(BaseModel):
    credential: CredentialResponse


class CredentialServiceOptionsResponse(BaseModel):
    services: list[CredentialServiceResponse]
    total: int
    page: int
    pages: int
    per: str


router = APIRouter(
    tags=["credentials"],
    responses={
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
)
_NO_STORE = {"Cache-Control": "no-store"}


def _per_page(raw: str) -> int | None:
    if raw == "all" or (
        len(raw) <= 10 and raw.isascii() and raw.isdecimal()
        and int(raw) in pagination_queries.PER_PAGE_OPTIONS
    ):
        return pagination_queries.resolve_per_page(raw)
    return 25


@router.put("/credentials/{cred_id}", response_model=MutationResponse)
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
    """Replace editable scalar fields, preserving all host/service associations."""
    cred = ownership_queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if host_id is not None and ownership_queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    try:
        values = commands.CredentialValues.parse(kind, username, secret, notes)
    except commands.InvalidCommand as exc:
        return invalid_command(exc, status_code=422)
    values.apply(cred)
    session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)


@router.get("/credentials", response_model=CredentialsPageResponse)
def credentials_page(
    filter: str = "",
    kind: str = "",
    scope: str = "",
    page: int = 1,
    per: str = "25",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """List identities and association counts without fetching credential secrets."""
    per_page = _per_page(per)
    result = credential_queries.credential_summaries(
        session, filter, kind, scope, engagement_id=engagement_id,
        page=page, per_page=per_page,
    )
    return JSONResponse(encode_page({
        "credentials": result.credentials, "total": result.total, "matched": result.matched,
        "page": result.page, "pages": result.pages,
        "per": "all" if per_page is None else str(per_page),
        "kinds": list(CredKind), "q": filter, "kind": kind, "scope": scope,
    }), headers=_NO_STORE)


@router.get("/credentials/{cred_id}", response_model=CredentialDetailResponse)
def credential_detail(
    cred_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Reveal one owned credential and its linked associations."""
    credential = credential_queries.credential_view(session, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(
            status_code=404, detail="credential not found", headers=_NO_STORE,
        )
    return JSONResponse(encode_page({"credential": credential}), headers=_NO_STORE)


@router.get(
    "/credentials/{cred_id}/options/services", response_model=CredentialServiceOptionsResponse,
)
def credential_service_options(
    cred_id: int,
    q: str = "",
    page: int = 1,
    per: str = "25",
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    if session.exec(select(Credential.id).where(
        Credential.id == cred_id, Credential.engagement_id == engagement_id,
    )).first() is None:
        raise HTTPException(status_code=404, detail="credential not found", headers=_NO_STORE)
    per_page = _per_page(per)
    result = credential_queries.credential_service_options(
        session, cred_id, engagement_id=engagement_id, q=q, page=page, per_page=per_page,
    )
    return JSONResponse(encode_page({
        "services": result.services, "total": result.total,
        "page": result.page, "pages": result.pages,
        "per": "all" if per_page is None else str(per_page),
    }), headers=_NO_STORE)


@router.post("/credentials", response_model=MutationResponse)
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
        return invalid_command(exc, status_code=422)
    selected_hosts = set(host_ids)
    selected_services = set(service_ids)
    for host_id in selected_hosts:
        if ownership_queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
            return JSONResponse({"detail": "host not found"}, status_code=422, headers=_NO_STORE)
    for service_id in selected_services:
        service = ownership_queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
        if service is None:
            return JSONResponse({"detail": "service not found"}, status_code=422, headers=_NO_STORE)
        if service.host_id not in selected_hosts:
            return JSONResponse(
                {"detail": "service must belong to a selected host"}, status_code=422,
                headers=_NO_STORE,
            )
    credential = Credential(engagement_id=engagement_id)
    values.apply(credential)
    session.add(credential)
    session.flush()
    assert credential.id is not None
    for host_id in selected_hosts:
        host = ownership_queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
        assert host is not None
        commands.link_credential_host(session, credential, host)
    session.flush()  # Service guards must see every staged host association.
    for service_id in selected_services:
        service = ownership_queries.get_owned(session, Service, service_id, engagement_id=engagement_id)
        assert service is not None
        commands.link_credential_service(session, credential, service)
    session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)


@router.delete("/credentials/{cred_id}", response_model=MutationResponse)
def delete_credential(
    cred_id: int,
    host_id: int | None = Form(None),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    cred = ownership_queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if cred is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if host_id is not None and ownership_queries.get_owned(session, Host, host_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="host not found")
    session.delete(cred)  # FK cascade drops its host/service link rows.
    session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)


@router.patch("/credentials/{cred_id}/hosts", response_model=MutationResponse)
def link_cred_host(
    cred_id: int,
    host_id: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Add one host association without replacing existing associations."""
    hid = int(host_id) if host_id.strip().isdigit() else None
    credential = ownership_queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if hid is None:
        raise HTTPException(status_code=422, detail="Select a host, then choose Link host.")
    host = ownership_queries.get_owned(session, Host, hid, engagement_id=engagement_id)
    if host is None:
        raise HTTPException(status_code=404, detail="Host is no longer available. Reload credentials and select another host.")
    commands.link_credential_host(session, credential, host)
    session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)


@router.delete("/credentials/{cred_id}/hosts/{host_id}", response_model=MutationResponse)
def unlink_cred_host(
    cred_id: int,
    host_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    credential = ownership_queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="credential not found")
    host = ownership_queries.get_owned(session, Host, host_id, engagement_id=engagement_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    commands.unlink_credential_host(session, credential, host)
    session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)


@router.patch("/credentials/{cred_id}/services", response_model=MutationResponse)
def link_cred_service(
    cred_id: int,
    service_id: str = Form(""),
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    """Add one service association without replacing existing associations."""
    sid = int(service_id) if service_id.strip().isdigit() else None
    svc = ownership_queries.get_owned(session, Service, sid, engagement_id=engagement_id) if sid is not None else None
    credential = ownership_queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if svc is None:
        raise HTTPException(
            status_code=422 if sid is None else 404,
            detail="Select an available service, then choose Link service. Reload credentials if the service is no longer available.",
        )
    try:
        commands.link_credential_service(session, credential, svc)
    except commands.InvalidCommand as exc:
        return invalid_command(exc, status_code=422)
    session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)


@router.delete("/credentials/{cred_id}/services/{service_id}", response_model=MutationResponse)
def unlink_cred_service(
    cred_id: int,
    service_id: int,
    engagement_id: str = Depends(require_engagement),
    session: Session = Depends(get_session),
) -> Response:
    if ownership_queries.get_owned(session, Credential, cred_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="credential not found")
    if ownership_queries.get_owned(session, Service, service_id, engagement_id=engagement_id) is None:
        raise HTTPException(status_code=404, detail="service not found")
    link = ownership_queries.get_owned(session, CredentialService, (cred_id, service_id), engagement_id=engagement_id)
    if link is not None:
        session.delete(link)
        session.commit()
    return JSONResponse({"ok": True}, headers=_NO_STORE)
