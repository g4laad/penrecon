from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, or_, select as sql_select
from sqlmodel import Session, col, select

from penrecon.models import OperationLog
from penrecon.queries.pagination import _page_bounds


@dataclass
class OperationSummary:
    id: int
    started_at: datetime | None
    destination: str
    tool: str
    command: str


@dataclass
class OperationPage:
    operations: list[OperationSummary]
    total: int
    page: int
    pages: int


def operation_logs(
    session: Session, q: str = "", *, engagement_id: str,
    page: int = 1, per_page: int | None = 25,
) -> OperationPage:
    """Search/count/page in SQLite without loading off-page summaries or bodies."""
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
    total = session.execute(
        sql_select(func.count()).select_from(statement.subquery()),
    ).scalar_one()
    page, pages = _page_bounds(total, page, per_page)
    statement = statement.order_by(
        col(OperationLog.started_at).is_(None),
        col(OperationLog.started_at).desc(),
        col(OperationLog.created_at).desc(),
        col(OperationLog.id),
    )
    if per_page is not None:
        statement = statement.limit(per_page).offset((page - 1) * per_page)
    return OperationPage(
        [
            OperationSummary(oid, started_at, destination, tool, command)
            for oid, started_at, destination, tool, command
            in session.connection().execute(statement)
        ],
        total, page, pages,
    )
