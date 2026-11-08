from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import String, case, cast, func, literal, select, union_all
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.selectable import CTE
from sqlmodel import Session, col

from penrecon.models import Host, Observation, ObsState, Scan
from penrecon.queries.ownership import get_owned
from penrecon.queries.pagination import _page_bounds


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
    total: int = 0
    page: int = 1
    pages: int = 1


def _summary() -> ColumnElement[str]:
    # Enum storage uses member names, while the existing formatted summaries
    # use values such as "open|filtered". Only null/empty fields are omitted:
    # whitespace and equivalent distributions across fields stay significant.
    summary: ColumnElement[str] = case(
        {state.name: state.value for state in ObsState},
        value=cast(col(Observation.state), String),
    )
    for value in (
        col(Observation.service_name),
        col(Observation.product),
        col(Observation.version),
    ):
        summary = summary + case((value != "", literal(" ") + value), else_="")
    return summary


def _snapshot(scan_id: int, *, engagement_id: str) -> CTE:
    # Keep the last observation per snapshot key, as the previous dictionary
    # comparison did, without loading observations or their extra JSON.
    latest = (
        select(func.max(col(Observation.id)).label("id"))
        .where(
            col(Observation.engagement_id) == engagement_id,
            col(Observation.scan_id) == scan_id,
        )
        .group_by(
            col(Observation.host_id),
            col(Observation.port),
            col(Observation.proto),
        )
    )
    return (
        select(
            col(Host.ip).label("ip"),
            col(Observation.port).label("port"),
            col(Observation.proto).label("proto"),
            _summary().label("summary"),
        )
        .select_from(Observation)
        .join(Host, col(Host.id) == col(Observation.host_id))
        .where(
            col(Observation.id).in_(latest),
            col(Observation.engagement_id) == engagement_id,
            col(Host.engagement_id) == engagement_id,
            col(Observation.scan_id) == scan_id,
        )
        .cte()
    )


def diff_scans(
    session: Session,
    scan_a_id: int,
    scan_b_id: int,
    *,
    engagement_id: str,
    page: int = 1,
    per_page: int | None = 25,
) -> DiffResult:
    a = get_owned(session, Scan, scan_a_id, engagement_id=engagement_id)
    b = get_owned(session, Scan, scan_b_id, engagement_id=engagement_id)
    if a is None or b is None:
        raise ValueError("scan not found")
    if scan_a_id == scan_b_id:
        return DiffResult(scan_a=a, scan_b=b)

    before = _snapshot(scan_a_id, engagement_id=engagement_id)
    after = _snapshot(scan_b_id, engagement_id=engagement_id)
    # Group the two snapshots rather than joining them: SQLite can choose
    # quadratic nested scans for outer joins against computed snapshot columns.
    observations = union_all(
        select(
            before.c.ip,
            before.c.port,
            before.c.proto,
            before.c.summary.label("before"),
            cast(literal(None), String).label("after"),
        ),
        select(
            after.c.ip,
            after.c.port,
            after.c.proto,
            cast(literal(None), String),
            after.c.summary,
        ),
    ).subquery()
    paired = (
        select(
            observations.c.ip,
            observations.c.port,
            observations.c.proto,
            func.max(observations.c.before).label("before"),
            func.max(observations.c.after).label("after"),
        )
        .group_by(
            observations.c.ip,
            observations.c.port,
            observations.c.proto,
        )
        .subquery()
    )
    differences = (
        select(
            paired.c.ip,
            paired.c.port,
            paired.c.proto,
            case(
                (paired.c.before.is_(None), "added"),
                (paired.c.after.is_(None), "removed"),
                else_="changed",
            ).label("kind"),
            paired.c.before,
            paired.c.after,
            case(
                (paired.c.before.is_(None), 0),
                (paired.c.after.is_(None), 1),
                else_=2,
            ).label("kind_order"),
        )
        .where(
            paired.c.before.is_(None)
            | paired.c.after.is_(None)
            | (paired.c.before != paired.c.after),
        )
        .subquery()
    )
    total = session.execute(select(func.count()).select_from(differences)).scalar_one()
    page, pages = _page_bounds(total, page, per_page)
    statement = select(
        differences.c.ip,
        differences.c.port,
        differences.c.proto,
        differences.c.kind,
        differences.c.before,
        differences.c.after,
    ).order_by(
        differences.c.kind_order,
        differences.c.ip,
        differences.c.port,
        differences.c.proto,
    )
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    return DiffResult(
        scan_a=a,
        scan_b=b,
        entries=[DiffEntry(*row) for row in session.execute(statement)],
        total=total,
        page=page,
        pages=pages,
    )
