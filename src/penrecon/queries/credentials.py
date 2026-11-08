from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import String, cast as sql_cast, func, or_, select as sql_select
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import Session, col, select

from penrecon import projections
from penrecon.models import (
    Credential, CredentialHost, CredentialService, CurrentService, Host, Service,
)
from penrecon.queries.ownership import get_owned
from penrecon.queries.pagination import _page_bounds


@dataclass
class LinkedHost:
    host_id: int
    ip: str


@dataclass
class CredentialHit:
    """Search identity and navigation only; never includes credential secrets."""

    id: int
    kind: str
    username: str
    hosts: list[LinkedHost]


@dataclass
class LinkedService:
    service_id: int
    host_id: int
    ip: str
    port: int
    proto: str
    name: str | None  # current display name (manual override or latest observation)


@dataclass
class CredentialView:
    id: int
    kind: str
    username: str
    secret: str
    notes: str
    created_at: str
    hosts: list[LinkedHost]
    services: list[LinkedService]


@dataclass
class CredentialSummary:
    id: int
    kind: str
    username: str
    notes_preview: str
    host_count: int
    service_count: int


@dataclass
class CredentialsPage:
    credentials: list[CredentialSummary]
    total: int
    matched: int
    page: int
    pages: int


@dataclass
class CredentialServicePage:
    services: list[LinkedService]
    total: int
    page: int
    pages: int


@dataclass
class HostCredentialView:
    """Editable credential values and associations for exactly one host."""

    id: int
    kind: str
    username: str
    secret: str
    notes: str
    hosts: list[LinkedHost]
    services: list[LinkedService]


def _credential_conditions(
    engagement_id: str, q: str, kind: str, scope: str,
) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [col(Credential.engagement_id) == engagement_id]
    if kind:
        conditions.append(col(Credential.kind) == kind)
    host_link = select(CredentialHost.credential_id).where(
        CredentialHost.engagement_id == engagement_id,
        CredentialHost.credential_id == Credential.id,
    ).exists()
    service_link = select(CredentialService.credential_id).where(
        CredentialService.engagement_id == engagement_id,
        CredentialService.credential_id == Credential.id,
    ).exists()
    if scope == "linked":
        conditions.append(or_(host_link, service_link))
    elif scope == "unlinked":
        conditions.append(~or_(host_link, service_link))
    elif scope:
        conditions.append(col(Credential.id).is_(None))
    if q:
        # Ordered scalar aggregates preserve the old joined-text substring
        # behavior, including matches spanning adjacent fields or associations.
        host_text = (
            sql_select(col(Host.ip).label("text"))
            .select_from(CredentialHost)
            .join(Host, col(Host.id) == col(CredentialHost.host_id))
            .where(
                col(CredentialHost.engagement_id) == engagement_id,
                col(CredentialHost.credential_id) == col(Credential.id),
                col(Host.engagement_id) == engagement_id,
            )
            .order_by(Host.ip, col(Host.id))
            .correlate(Credential).subquery()
        )
        service_text = (
            sql_select((
                col(Host.ip) + ":" + sql_cast(col(CurrentService.port), String)
                + "/" + col(CurrentService.proto) + " "
                + func.coalesce(col(CurrentService.service_name), "")
            ).label("text"))
            .select_from(CredentialService)
            .join(CurrentService, col(CurrentService.service_id) == col(CredentialService.service_id))
            .join(Host, col(Host.id) == col(CurrentService.host_id))
            .where(
                col(CredentialService.engagement_id) == engagement_id,
                col(CredentialService.credential_id) == col(Credential.id),
                col(CurrentService.engagement_id) == engagement_id,
                col(Host.engagement_id) == engagement_id,
            )
            .order_by(Host.ip, col(CurrentService.port), CurrentService.proto, col(CurrentService.service_id))
            .correlate(Credential).subquery()
        )
        host_suffix = sql_select(func.group_concat(host_text.c.text, " ").cast(String)).scalar_subquery()
        service_suffix = sql_select(func.group_concat(service_text.c.text, " ").cast(String)).scalar_subquery()
        text = (
            col(Credential.username) + " " + sql_cast(col(Credential.kind), String)
            + " " + col(Credential.notes)
            + func.coalesce(" " + host_suffix, "")
            + func.coalesce(" " + service_suffix, "")
        )
        conditions.append(func.instr(func.unicode_lower(text), q.lower()) > 0)
    return conditions


def credential_summaries(
    session: Session, q: str = "", kind: str = "", scope: str = "", *,
    engagement_id: str, page: int = 1, per_page: int | None = 25,
) -> CredentialsPage:
    """Filter/count/page identities in SQL; count links only for the selected page."""
    if q:
        projections.prepare_read(session)
    conditions = _credential_conditions(engagement_id, q, kind, scope)
    total = session.exec(select(func.count()).select_from(Credential).where(
        Credential.engagement_id == engagement_id,
    )).one()
    matched = session.exec(
        select(func.count()).select_from(Credential).where(*conditions),
    ).one() if q or kind or scope else total
    page, pages = _page_bounds(matched, page, per_page)
    statement = sql_select(
        col(Credential.id), col(Credential.kind), col(Credential.username),
        func.substr(col(Credential.notes), 1, 160),
    ).where(*conditions).order_by(
        col(Credential.created_at).desc(), col(Credential.id).desc(),
    )
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    rows = session.connection().execute(statement).all()
    ids = [row[0] for row in rows]
    counts: list[dict[int, int]] = []
    for link in (CredentialHost, CredentialService):
        counts.append(dict(session.exec(
            select(link.credential_id, func.count()).where(
                link.engagement_id == engagement_id, col(link.credential_id).in_(ids),
            ).group_by(col(link.credential_id)),
        ).all()) if ids else {})
    return CredentialsPage([
        CredentialSummary(cid, credential_kind, username, notes, counts[0].get(cid, 0), counts[1].get(cid, 0))
        for cid, credential_kind, username, notes in rows
    ], total, matched, page, pages)


def _credential_links(
    session: Session, credential_ids: set[int], *, engagement_id: str,
    host_id: int | None = None,
) -> tuple[dict[int, list[LinkedHost]], dict[int, list[LinkedService]]]:
    """Fetch narrow association columns, optionally scoped to one displayed host."""
    if not credential_ids:
        return {}, {}
    projections.prepare_read(session)
    host_statement = (
        select(CredentialHost.credential_id, Host.id, Host.ip)
        .join(Host, col(Host.id) == col(CredentialHost.host_id))
        .where(
            CredentialHost.engagement_id == engagement_id, Host.engagement_id == engagement_id,
            col(CredentialHost.credential_id).in_(credential_ids),
        )
    )
    service_statement = (
        sql_select(
            col(CredentialService.credential_id), col(CurrentService.service_id), col(CurrentService.host_id),
            col(Host.ip), col(CurrentService.port), col(CurrentService.proto), col(CurrentService.service_name),
        )
        .join(CurrentService, col(CurrentService.service_id) == col(CredentialService.service_id))
        .join(Host, col(Host.id) == col(CurrentService.host_id))
        .where(
            col(CredentialService.engagement_id) == engagement_id,
            col(CredentialService.credential_id).in_(credential_ids),
            col(CurrentService.engagement_id) == engagement_id, col(Host.engagement_id) == engagement_id,
        )
    )
    if host_id is not None:
        host_statement = host_statement.where(Host.id == host_id)
        service_statement = service_statement.where(col(CurrentService.host_id) == host_id)
    hosts_by_cred: dict[int, list[LinkedHost]] = defaultdict(list)
    for cid, hid, ip in session.exec(host_statement.order_by(Host.ip, col(Host.id))):
        if hid is not None:
            hosts_by_cred[cid].append(LinkedHost(hid, ip))
    services_by_cred: dict[int, list[LinkedService]] = defaultdict(list)
    for cid, sid, hid, ip, port, proto, name in session.execute(service_statement.order_by(
        Host.ip, col(CurrentService.port), CurrentService.proto, col(CurrentService.service_id),
    )):
        services_by_cred[cid].append(LinkedService(sid, hid, ip, port, proto, name))
    return hosts_by_cred, services_by_cred


def credential_view(
    session: Session, credential_id: int, *, engagement_id: str,
) -> CredentialView | None:
    """Full editable projection of one owned credential and its associations."""
    credential = get_owned(session, Credential, credential_id, engagement_id=engagement_id)
    if credential is None:
        return None
    hosts, services = _credential_links(session, {credential_id}, engagement_id=engagement_id)
    return CredentialView(
        credential_id, credential.kind, credential.username, credential.secret, credential.notes,
        credential.created_at.strftime("%Y-%m-%d %H:%M"),
        hosts.get(credential_id, []), services.get(credential_id, []),
    )


def credential_service_options(
    session: Session, credential_id: int, *, engagement_id: str,
    q: str = "", page: int = 1, per_page: int | None = 25,
) -> CredentialServicePage:
    """Page unlinked current services of explicitly linked hosts on demand."""
    projections.prepare_read(session)
    linked_hosts = select(CredentialHost.host_id).where(
        CredentialHost.engagement_id == engagement_id,
        CredentialHost.credential_id == credential_id,
    )
    linked_service = select(CredentialService.service_id).where(
        CredentialService.engagement_id == engagement_id,
        CredentialService.credential_id == credential_id,
        CredentialService.service_id == CurrentService.service_id,
    ).exists()
    conditions: list[ColumnElement[bool]] = [
        col(CurrentService.engagement_id) == engagement_id,
        col(Host.engagement_id) == engagement_id,
        col(CurrentService.host_id).in_(linked_hosts), ~linked_service,
    ]
    if q:
        text = (
            col(Host.ip) + ":" + sql_cast(col(CurrentService.port), String) + "/"
            + col(CurrentService.proto) + " " + func.coalesce(col(CurrentService.service_name), "")
        )
        conditions.append(func.instr(func.unicode_lower(text), q.lower()) > 0)
    base = sql_select().select_from(CurrentService).join(
        Host, col(Host.id) == col(CurrentService.host_id),
    ).where(*conditions)
    total = session.connection().execute(base.with_only_columns(func.count())).scalar_one()
    page, pages = _page_bounds(total, page, per_page)
    statement = base.with_only_columns(
        col(CurrentService.service_id), col(CurrentService.host_id), col(Host.ip),
        col(CurrentService.port), col(CurrentService.proto), col(CurrentService.service_name),
    ).order_by(Host.ip, col(CurrentService.port), CurrentService.proto, col(CurrentService.service_id))
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    return CredentialServicePage(
        [LinkedService(*row) for row in session.connection().execute(statement)],
        total, page, pages,
    )


def credentials_for_host(
    session: Session, host_id: int, *, engagement_id: str,
) -> list[HostCredentialView]:
    """Editable credentials and links for this host, never other hosts or picker pools."""
    host_link = select(CredentialHost.credential_id).where(
        CredentialHost.engagement_id == engagement_id,
        CredentialHost.credential_id == Credential.id, CredentialHost.host_id == host_id,
    ).exists()
    service_link = (
        select(CredentialService.credential_id)
        .join(Service, col(Service.id) == col(CredentialService.service_id))
        .where(
            CredentialService.engagement_id == engagement_id,
            CredentialService.credential_id == Credential.id,
            Service.engagement_id == engagement_id, Service.host_id == host_id,
        ).exists()
    )
    rows = session.connection().execute(sql_select(
        col(Credential.id), col(Credential.kind), col(Credential.username),
        col(Credential.secret), col(Credential.notes),
    ).where(
        col(Credential.engagement_id) == engagement_id, or_(host_link, service_link),
    ).order_by(col(Credential.created_at).desc(), col(Credential.id).desc())).all()
    hosts, services = _credential_links(
        session, {row[0] for row in rows}, engagement_id=engagement_id, host_id=host_id,
    )
    return [
        HostCredentialView(cid, kind, username, secret, notes, hosts.get(cid, []), services.get(cid, []))
        for cid, kind, username, secret, notes in rows
    ]
