from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, String, func, select as sql_select
from sqlalchemy.orm import Mapped
from sqlalchemy.sql.elements import ColumnElement
from sqlmodel import Session, col, select

from penrecon import projections
from penrecon.history import HostTimeline, Overrides, State, timeline
from penrecon.models import (
    Annotation, CurrentService, Hostname, HostHostname, HostScanState,
    HostSummary, HostSummaryTag, Observation, Service,
)
from penrecon.queries.pagination import _page_bounds


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
