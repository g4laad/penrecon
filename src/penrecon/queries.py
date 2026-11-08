"""Read-side helpers: current-state merge, host listing/detail, scan diff,
and annotation access.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Generator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar

from sqlalchemy import Select, String, cast as sql_cast, func, inspect, or_, select as sql_select
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import Session, col, select

from penrecon.history import HostTimeline, Overrides, State, timeline
from penrecon import projections
from penrecon.models import (
    Annotation,
    Credential,
    CredentialHost,
    CredentialService,
    CurrentService,
    EngagementOwned,
    Host,
    Hostname,
    HostHostname,
    HostScanState,
    HostSummary,
    HostSummaryTag,
    Note,
    Observation,
    OperationLog,
    Scan,
    Service,
    Status,
)


@dataclass
class ServiceView:
    service_id: int
    port: int
    proto: str
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    last_seen: str
    annotation: Annotation | None
    overrides: Overrides
    manual: bool = False


@dataclass
class HostRow:
    id: int
    ip: str
    hostnames: list[str]
    open_count: int
    status: str
    tags: list[str]
    open_ports: list[int]
    service_names: list[str]
    open_services: list[tuple[int, str | None]]  # (port, service_name), port-sorted
    change: str = ""  # "new" | "changed" | "" — scan-delta marker
    triaged: bool = False  # has an annotation; un-triaged hosts wear only the default status


@dataclass
class HostPage:
    rows: list[HostRow]
    total: int
    matched: int
    page: int
    pages: int


@dataclass
class ServicePage:
    services: list[ServiceView]
    total: int
    page: int
    pages: int


@dataclass
class DiffEntry:
    ip: str
    port: int
    proto: str
    kind: str  # added | removed | changed
    before: str | None = None
    after: str | None = None


@dataclass
class DiffResult:
    scan_a: Scan
    scan_b: Scan
    entries: list[DiffEntry] = field(default_factory=list)


@dataclass
class NoteHit:
    """One note matched by an engagement-wide search, linked back to its target."""

    href: str
    where: str  # human label of the annotated entity (IP, IP·port/proto, hostname)
    kind: str  # "host" | "service" | "hostname"
    title: str
    preview: str


@dataclass
class SearchResults:
    q: str
    hosts: list[HostRow] = field(default_factory=list)
    notes: list[NoteHit] = field(default_factory=list)
    credentials: list[CredentialHit] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.hosts) + len(self.notes) + len(self.credentials)


_Owned = TypeVar("_Owned", bound=EngagementOwned)


def get_owned(
    session: Session,
    model: type[_Owned],
    identity: int | tuple[int, ...],
    *,
    engagement_id: str,
) -> _Owned | None:
    """Fetch an entity or link by its existing primary key within an engagement."""
    values = identity if isinstance(identity, tuple) else (identity,)
    mapper = inspect(model)
    assert mapper is not None
    primary_key = mapper.primary_key
    if len(values) != len(primary_key):
        raise ValueError("identity does not match the model primary key")
    return session.exec(
        select(model).where(
            model.engagement_id == engagement_id,
            *(column == value for column, value in zip(primary_key, values, strict=True)),
        )
    ).first()


# --- annotations ---------------------------------------------------------------

def get_annotation(
    session: Session, *, engagement_id: str,
    host_id: int | None = None, service_id: int | None = None
) -> Annotation | None:
    """The triage annotation for a host or service. Pass exactly one id."""
    assert (host_id is None) != (service_id is None), "pass exactly one target id"
    if host_id is not None:
        return session.exec(
            select(Annotation).where(
                Annotation.engagement_id == engagement_id, Annotation.host_id == host_id
            )
        ).first()
    return session.exec(
        select(Annotation).where(
            Annotation.engagement_id == engagement_id, Annotation.service_id == service_id
        )
    ).first()


def upsert_annotation(
    session: Session,
    status: Status,
    tags: list[str],
    *,
    engagement_id: str,
    host_id: int | None = None,
    service_id: int | None = None,
) -> Annotation:
    """Save a free status classification and tags; existence means triaged.

    No status is terminal and returning to ``new`` does not remove triage.
    """
    ann = get_annotation(
        session, host_id=host_id, service_id=service_id, engagement_id=engagement_id
    )
    if ann is None:
        ann = Annotation(engagement_id=engagement_id, host_id=host_id, service_id=service_id)
        session.add(ann)
    ann.status = status
    ann.tags = tags
    ann.updated_at = datetime.now(UTC)
    session.commit()
    return ann


def notes_for(session: Session, host_id: int, *, engagement_id: str) -> list[Note]:
    """All notes on a host, oldest first."""
    return list(
        session.exec(
            select(Note)
            .where(Note.engagement_id == engagement_id, Note.host_id == host_id)
            .order_by(Note.created_at)  # type: ignore[arg-type]
        ).all()
    )


# --- operation log ------------------------------------------------------------

@dataclass
class OperationSummary:
    id: int
    started_at: datetime | None
    destination: str
    tool: str
    command: str


def operation_logs(session: Session, q: str = "", *, engagement_id: str) -> list[OperationSummary]:
    """Timeline summaries; search full text in SQL without loading detail bodies."""
    statement = sql_select(
        col(OperationLog.id), col(OperationLog.started_at), col(OperationLog.destination),
        col(OperationLog.tool), col(OperationLog.command),
    ).where(col(OperationLog.engagement_id) == engagement_id)
    needle = q.strip().casefold()
    if needle:
        tags = func.json_each(OperationLog.tags).table_valued("value")
        tag_match = select(tags.c.value).where(
            func.instr(func.casefold(tags.c.value), needle) > 0,
        ).exists()
        statement = statement.where(or_(
            *(
                func.instr(func.casefold(value), needle) > 0
                for value in (
                    OperationLog.source, OperationLog.destination, OperationLog.tool,
                    OperationLog.user_context, OperationLog.command, OperationLog.output,
                    OperationLog.description, OperationLog.comments, OperationLog.attachment_name,
                )
            ),
            tag_match,
        ))
    statement = statement.order_by(
        col(OperationLog.started_at).is_(None),
        col(OperationLog.started_at).desc(),
        col(OperationLog.created_at).desc(),
    )
    return [
        OperationSummary(oid, started_at, destination, tool, command)
        for oid, started_at, destination, tool, command in session.connection().execute(statement)
        if oid is not None
    ]


# --- current-state merge -------------------------------------------------------

def latest_observations(
    session: Session, host_id: int, *, engagement_id: str
) -> dict[tuple[int, str], Observation]:
    """Persisted latest trustworthy scan evidence; manual overrides stay separate."""
    return projections.latest_for_host(session, host_id, engagement_id=engagement_id)


def host_hostnames(
    session: Session, host_id: int, *, engagement_id: str
) -> list[tuple[int, str]]:
    """(hostname_id, name) for a host, excluding manually-hidden links."""
    rows = session.exec(
        select(Hostname.id, Hostname.name)
        .join(HostHostname, HostHostname.hostname_id == Hostname.id)  # type: ignore[arg-type]
        .where(
            Hostname.engagement_id == engagement_id,
            HostHostname.engagement_id == engagement_id,
            HostHostname.host_id == host_id, HostHostname.hidden == False,  # noqa: E712
        )
        .order_by(Hostname.name)
    ).all()
    return [(hid, name) for hid, name in rows if hid is not None]


def _service_name(svc: Service, observation: Observation | None) -> str | None:
    """Manual names override the latest observation, including a missing name."""
    return svc.m_service_name or (observation.service_name if observation else None)


def service_state(svc: Service, observation: Observation | None) -> State:
    """Resolve the effective values shared by inventory and manual snapshots."""
    return State(
        state=str(svc.m_state or (observation.state if observation else None) or "unknown"),
        service_name=_service_name(svc, observation),
        product=svc.m_product or (observation.product if observation else None),
        version=svc.m_version or (observation.version if observation else None),
    )


def service_overrides(svc: Service) -> Overrides:
    """Raw override values, including nulls that inherit scan evidence."""
    return Overrides(
        state=str(svc.m_state) if svc.m_state is not None else None,
        service_name=svc.m_service_name, product=svc.m_product, version=svc.m_version,
    )


def _service_statement(
    host_id: int, engagement_id: str,
) -> Select[tuple[CurrentService, Service, Annotation]]:
    return sql_select(CurrentService, Service, Annotation).join(
        Service,
        (col(Service.id) == col(CurrentService.service_id))
        & (col(Service.engagement_id) == col(CurrentService.engagement_id)),
    ).outerjoin(
        Annotation,
        (col(Annotation.service_id) == col(CurrentService.service_id))
        & (col(Annotation.engagement_id) == col(CurrentService.engagement_id)),
    ).where(
        col(CurrentService.engagement_id) == engagement_id,
        col(CurrentService.host_id) == host_id,
    )


def _service_view(
    current: CurrentService, service: Service, annotation: Annotation | None,
) -> ServiceView:
    return ServiceView(
        service_id=current.service_id, port=current.port, proto=current.proto,
        state=current.state, service_name=current.service_name,
        product=current.product, version=current.version, last_seen=current.last_seen,
        annotation=annotation, overrides=service_overrides(service), manual=current.manual,
    )


def resolved_services(
    session: Session, host_id: int, *, engagement_id: str,
) -> list[ServiceView]:
    """Read effective service values without decoding scan-state JSON."""
    projections.prepare_read(session)
    statement = _service_statement(host_id, engagement_id).order_by(
        col(CurrentService.port), col(CurrentService.proto), col(CurrentService.service_id),
    )
    return [_service_view(*row) for row in session.execute(statement)]


def host_timeline(
    session: Session, host_id: int, *, engagement_id: str,
    page: int = 1, show_unchanged: bool = False,
) -> HostTimeline:
    """Newest-first scans and manual actions, merged before 20-entry pagination.

    Unchanged scans are opt-in; every recorded manual action remains visible.
    """
    return timeline(
        session, host_id, engagement_id=engagement_id,
        page=page, show_unchanged=show_unchanged,
    )


def host_change(
    session: Session, host_id: int, *, engagement_id: str,
) -> str:
    """Scan-only marker, unaffected by manual actions in the unified timeline.

    Preserve the first-sighting baseline rule: only a host introduced in the
    latest imported scan is new, and only when an earlier scan exists.
    Otherwise ``changed`` describes the last scan of this host, not freshness:
    unrelated later scans and manual actions do not clear it. Missing evidence
    never expires an open service.
    """
    projections.prepare_read(session)
    change = session.exec(
        select(HostScanState.change).where(
            HostScanState.engagement_id == engagement_id,
            HostScanState.host_id == host_id,
        )
    ).first()
    return change or ""


def _host_row(summary: HostSummary) -> HostRow:
    open_services = [(port, name) for port, name in summary.open_services]
    return HostRow(
        id=summary.host_id, ip=summary.ip, hostnames=summary.hostnames,
        open_count=summary.open_count, status=summary.status, tags=summary.tags,
        open_ports=[port for port, _ in open_services],
        service_names=sorted({name for _, name in open_services if name}),
        open_services=open_services, change=summary.change, triaged=summary.triaged,
    )


def _host_conditions(
    engagement_id: str, *, q: str = "", port: int | None = None,
    tag: str = "", status: str = "", change: str = "",
) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [
        col(HostSummary.engagement_id) == engagement_id,
    ]
    if q:
        values = func.json_each(HostSummary.search_values).table_valued("value")
        conditions.append(sql_select(values.c.value).where(
            func.instr(values.c.value, q.lower()) > 0,
        ).exists())
    if port is not None:
        conditions.append(col(HostSummary.host_id).in_(
            sql_select(col(CurrentService.host_id)).where(
                col(CurrentService.engagement_id) == engagement_id,
                col(CurrentService.port) == port,
                col(CurrentService.state) == "open",
            ),
        ))
    if tag:
        conditions.append(col(HostSummary.host_id).in_(
            sql_select(col(HostSummaryTag.host_id)).where(
                col(HostSummaryTag.engagement_id) == engagement_id,
                col(HostSummaryTag.tag) == tag,
            ),
        ))
    if status:
        conditions.append(col(HostSummary.status) == status)
    if change:
        conditions.append(col(HostSummary.change) == ("" if change == "unchanged" else change))
    return conditions


def host_rows(
    session: Session, *, engagement_id: str, q: str = "",
    port: int | None = None, tag: str = "", status: str = "", change: str = "",
) -> list[HostRow]:
    """All matching materialized hosts; paginated consumers use host_page()."""
    projections.prepare_read(session)
    statement = select(HostSummary).where(*_host_conditions(
        engagement_id, q=q, port=port, tag=tag, status=status, change=change,
    )).order_by(HostSummary.ip, col(HostSummary.host_id))
    return [_host_row(summary) for summary in session.exec(statement)]


def host_page(
    session: Session, *, engagement_id: str, q: str = "",
    port: int | None = None, tag: str = "", status: str = "", change: str = "",
    sort: str = "change", direction: str = "asc", page: int = 1,
    per_page: int | None = 10,
) -> HostPage:
    """Filter/count/order in SQLite and materialize only the selected host page."""
    projections.prepare_read(session)
    conditions = _host_conditions(
        engagement_id, q=q, port=port, tag=tag, status=status, change=change,
    )
    total = session.exec(select(func.count()).select_from(HostSummary).where(
        HostSummary.engagement_id == engagement_id,
    )).one()
    matched = session.exec(
        select(func.count()).select_from(HostSummary).where(*conditions),
    ).one() if q or port is not None or tag or status or change else total
    page, pages = _page_bounds(matched, page, per_page)
    statement = select(HostSummary).where(*conditions)
    descending = direction == "desc"
    if sort == "change":
        rank = col(HostSummary.change_rank)
        statement = statement.order_by(
            rank.desc() if descending else rank.asc(), col(HostSummary.open_count).desc(),
        )
    elif sort == "ports":
        count = col(HostSummary.open_count)
        statement = statement.order_by(count.desc() if descending else count.asc())
    elif sort == "status":
        classification = col(HostSummary.status)
        statement = statement.order_by(
            classification.desc() if descending else classification.asc(),
        )
    else:
        ip = col(HostSummary.ip_sort)
        statement = statement.order_by(ip.desc() if descending else ip.asc())
    statement = statement.order_by(HostSummary.ip, col(HostSummary.host_id))
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    return HostPage(
        [_host_row(summary) for summary in session.exec(statement)],
        total, matched, page, pages,
    )


PER_PAGE_OPTIONS = (10, 25, 50)  # selectable page sizes; "all" (no limit) is the 4th choice
PER_PAGE_DEFAULT = 10

_Row = TypeVar("_Row")


def resolve_per_page(raw: str) -> int | None:
    """Map a ``?per`` query value to a row limit. ``"all"`` -> ``None`` (no
    limit); an empty/unknown/non-whitelisted value falls back to the default."""
    if raw == "all":
        return None
    if len(raw) <= 10 and raw.isascii() and raw.isdecimal():
        value = int(raw)
        if value in PER_PAGE_OPTIONS:
            return value
    return PER_PAGE_DEFAULT


def paginate(
    rows: list[_Row], page: int, per_page: int | None = PER_PAGE_DEFAULT
) -> tuple[list[_Row], int, int]:
    """Slice ``rows`` to one page. Returns ``(page_rows, page, pages)`` with
    ``page`` clamped into ``[1, pages]`` so an out-of-range or filtered-away
    page lands on the last real page rather than an empty table. ``per_page``
    of ``None`` means "all": one page holds every row."""
    if per_page is None:
        return list(rows), 1, 1
    pages = max(1, -(-len(rows) // per_page))  # ceil division
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    return rows[start : start + per_page], page, pages


SORT_DEFAULT_DIR = {"change": "asc", "ports": "desc", "ip": "asc", "status": "asc"}

def _page_bounds(total: int, page: int, per_page: int | None) -> tuple[int, int]:
    if per_page is None:
        return 1, 1
    pages = max(1, (total + per_page - 1) // per_page)
    return max(1, min(page, pages)), pages


SERVICE_SORT_DEFAULT_DIR = {"port": "asc", "state": "asc", "service": "asc", "status": "asc"}


def service_page(
    session: Session, host_id: int, *, engagement_id: str,
    port: str = "", state: str = "", service: str = "", status: str = "",
    sort: str = "port", direction: str = "asc", page: int = 1,
    per_page: int | None = 10,
) -> ServicePage:
    """Filter and paginate effective services before constructing display views."""
    projections.prepare_read(session)
    statement = _service_statement(host_id, engagement_id)
    if port.strip():
        statement = statement.where(func.instr(
            func.cast(col(CurrentService.port), String), port.strip(),
        ) > 0)
    if state:
        statement = statement.where(col(CurrentService.state) == state)
    if service.strip():
        statement = statement.where(
            func.instr(col(CurrentService.search_text), service.strip().lower()) > 0,
        )
    if status:
        statement = statement.where(col(Annotation.status) == status)
    total = session.execute(
        sql_select(func.count()).select_from(statement.subquery()),
    ).scalar_one()
    page, pages = _page_bounds(total, page, per_page)
    descending = direction == "desc"
    value: Mapped[Any] | ColumnElement[Any]
    if sort == "state":
        value = col(CurrentService.state)
    elif sort == "service":
        value = col(CurrentService.service_name_lower)
    elif sort == "status":
        value = func.coalesce(col(Annotation.status), "")
    else:
        value = col(CurrentService.port)
    statement = statement.order_by(
        value.desc() if descending else value.asc(),
        col(CurrentService.port).desc() if descending else col(CurrentService.port).asc(),
        col(CurrentService.proto), col(CurrentService.service_id),
    )
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    return ServicePage(
        [_service_view(*row) for row in session.execute(statement)], total, page, pages,
    )


# --- credentials ---------------------------------------------------------------

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


# --- diff ----------------------------------------------------------------------

def _obs_by_key(
    session: Session, scan_id: int, *, engagement_id: str
) -> dict[tuple[str, int, str], Observation]:
    stmt = (
        select(Observation, Host.ip)
        .join(Host, Host.id == Observation.host_id)  # type: ignore[arg-type]
        .where(
            Observation.engagement_id == engagement_id, Host.engagement_id == engagement_id,
            Observation.scan_id == scan_id,
        )
    )
    out: dict[tuple[str, int, str], Observation] = {}
    for obs, ip in session.exec(stmt).all():
        out[(ip, obs.port, obs.proto)] = obs
    return out


def _summary(o: Observation) -> str:
    parts: list[str] = [o.state]
    if o.service_name:
        parts.append(o.service_name)
    if o.product or o.version:
        parts.append(" ".join(p for p in (o.product, o.version) if p))
    return " ".join(parts)


def diff_scans(
    session: Session, scan_a_id: int, scan_b_id: int, *, engagement_id: str
) -> DiffResult:
    a = get_owned(session, Scan, scan_a_id, engagement_id=engagement_id)
    b = get_owned(session, Scan, scan_b_id, engagement_id=engagement_id)
    if a is None or b is None:
        raise ValueError("scan not found")
    result = DiffResult(scan_a=a, scan_b=b)
    obs_a = _obs_by_key(session, scan_a_id, engagement_id=engagement_id)
    obs_b = _obs_by_key(session, scan_b_id, engagement_id=engagement_id)

    for key in sorted(obs_b.keys() - obs_a.keys()):
        ip, port, proto = key
        result.entries.append(
            DiffEntry(ip, port, proto, "added", after=_summary(obs_b[key]))
        )
    for key in sorted(obs_a.keys() - obs_b.keys()):
        ip, port, proto = key
        result.entries.append(
            DiffEntry(ip, port, proto, "removed", before=_summary(obs_a[key]))
        )
    for key in sorted(obs_a.keys() & obs_b.keys()):
        sa, sb = _summary(obs_a[key]), _summary(obs_b[key])
        if sa != sb:
            ip, port, proto = key
            result.entries.append(DiffEntry(ip, port, proto, "changed", before=sa, after=sb))
    return result


# --- global search -------------------------------------------------------------

def _note_preview(body: str, ql: str, width: int = 200) -> str:
    """A short excerpt of the note body, windowed around the first match of ``ql``."""
    body = body.strip()
    if not body:
        return ""
    i = body.lower().find(ql)
    if i < 0:  # matched on a tag, not the body — show the body's opening
        return body[:width] + ("…" if len(body) > width else "")
    start = max(0, i - 60)
    end = min(len(body), i + len(ql) + 140)
    return ("…" if start else "") + body[start:end].strip() + ("…" if end < len(body) else "")


def search_notes(session: Session, ql: str, *, engagement_id: str) -> list[NoteHit]:
    """Notes whose title or body contains ``ql`` (already lowercased). Notes live
    only on hosts, and the FK cascade drops them with the host, so the host
    always exists (the None guard is just for the type checker)."""
    hits: list[NoteHit] = []
    for note in session.exec(select(Note).where(Note.engagement_id == engagement_id)).all():
        if ql not in note.title.lower() and ql not in note.body_md.lower():
            continue
        host = get_owned(session, Host, note.host_id, engagement_id=engagement_id)
        if host is None:  # ponytail: unreachable under FK, keeps mypy happy
            continue
        hits.append(
            NoteHit(
                href=f"/e/{engagement_id}/hosts/{host.id}", where=host.ip, kind="host",
                title=note.title, preview=_note_preview(note.body_md, ql),
            )
        )
    return hits


# --- export --------------------------------------------------------------------

EXPORT_COLUMNS = [
    "ip", "hostnames", "port", "proto", "state",
    "service", "product", "version", "status", "tags",
]

# characters that make a spreadsheet treat a cell as a formula (CSV injection)
_CSV_RISKY_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection. Scan-derived fields (service
    banners, hostnames) are attacker-controlled; a leading =/+/-/@ makes Excel
    or Calc execute the cell as a formula. Prefix such values with a quote so
    they open as literal text. CSV export only — never for HTML display."""
    return "'" + value if value.startswith(_CSV_RISKY_PREFIXES) else value


def export_rows(
    session: Session, *, engagement_id: str,
) -> Generator[dict[str, str], None, None]:
    """Stream effective inventory values, including hosts without services.

    Scalar projections avoid ORM identity-map growth; cursor fetches are bounded
    independently of the number of hosts or services in the engagement.
    """
    projections.prepare_read(session)
    statement = sql_select(
        col(HostSummary.ip), col(HostSummary.hostnames),
        col(HostSummary.status), col(HostSummary.tags),
        col(CurrentService.port), col(CurrentService.proto), col(CurrentService.state),
        col(CurrentService.service_name), col(CurrentService.product), col(CurrentService.version),
    ).outerjoin(
        CurrentService,
        (col(CurrentService.host_id) == col(HostSummary.host_id))
        & (col(CurrentService.engagement_id) == col(HostSummary.engagement_id)),
    ).where(
        col(HostSummary.engagement_id) == engagement_id,
    ).order_by(
        col(HostSummary.ip), col(CurrentService.port),
        col(CurrentService.proto), col(CurrentService.service_id),
    ).execution_options(yield_per=256)
    with session.execute(statement) as result:
        for ip, hostnames, status, tags, port, proto, state, name, product, version in result:
            yield {
                "ip": _csv_safe(ip),
                "hostnames": _csv_safe(" ".join(hostnames)),
                "status": status,
                "tags": _csv_safe(" ".join(tags)),
                "port": str(port) if port is not None else "",
                "proto": _csv_safe(proto or ""),
                "state": _csv_safe(state or ""),
                "service": _csv_safe(name or ""),
                "product": _csv_safe(product or ""),
                "version": _csv_safe(version or ""),
            }


def search(session: Session, q: str, *, engagement_id: str) -> SearchResults:
    """Search this engagement's hosts/hostnames/services, notes, tags and credentials.
    Empty queries return nothing (the page shows a hint instead)."""
    ql = q.strip().lower()
    if not ql:
        return SearchResults(q="")
    creds = [
        CredentialHit(cid, kind, username, [])
        for cid, kind, username, notes in session.exec(
            select(Credential.id, Credential.kind, Credential.username, Credential.notes)
            .where(Credential.engagement_id == engagement_id)
            .order_by(Credential.created_at.desc())  # type: ignore[attr-defined]
        ).all()
        if cid is not None and (ql in username.lower() or ql in notes.lower())
    ]
    if creds:
        hits_by_id = {c.id: c for c in creds}
        for cid, hid, ip in session.exec(
            select(CredentialHost.credential_id, Host.id, Host.ip)
            .join(Host, Host.id == CredentialHost.host_id)  # type: ignore[arg-type]
            .where(
                CredentialHost.engagement_id == engagement_id,
                Host.engagement_id == engagement_id,
                col(CredentialHost.credential_id).in_(hits_by_id),
            )
            .order_by(Host.ip)
        ).all():
            if hid is not None:
                hits_by_id[cid].hosts.append(LinkedHost(hid, ip))
    return SearchResults(
        q=q.strip(),
        hosts=host_rows(session, engagement_id=engagement_id, q=ql),
        notes=search_notes(session, ql, engagement_id=engagement_id),
        credentials=creds,
    )
