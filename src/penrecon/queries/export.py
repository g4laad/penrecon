from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import select as sql_select
from sqlmodel import Session, col

from penrecon import projections
from penrecon.models import CurrentService, HostSummary

EXPORT_COLUMNS = [
    "ip",
    "hostnames",
    "port",
    "proto",
    "state",
    "service",
    "product",
    "version",
    "status",
    "tags",
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
    session: Session,
    *,
    engagement_id: str,
) -> Generator[dict[str, str], None, None]:
    """Stream effective inventory values, including hosts without services.

    Scalar projections avoid ORM identity-map growth; cursor fetches are bounded
    independently of the number of hosts or services in the engagement.
    """
    projections.prepare_read(session)
    statement = (
        sql_select(
            col(HostSummary.ip),
            col(HostSummary.hostnames),
            col(HostSummary.status),
            col(HostSummary.tags),
            col(CurrentService.port),
            col(CurrentService.proto),
            col(CurrentService.state),
            col(CurrentService.service_name),
            col(CurrentService.product),
            col(CurrentService.version),
        )
        .outerjoin(
            CurrentService,
            (col(CurrentService.host_id) == col(HostSummary.host_id))
            & (col(CurrentService.engagement_id) == col(HostSummary.engagement_id)),
        )
        .where(
            col(HostSummary.engagement_id) == engagement_id,
        )
        .order_by(
            col(HostSummary.ip),
            col(CurrentService.port),
            col(CurrentService.proto),
            col(CurrentService.service_id),
        )
        .execution_options(yield_per=256)
    )
    with session.execute(statement) as result:
        for (
            ip,
            hostnames,
            status,
            tags,
            port,
            proto,
            state,
            name,
            product,
            version,
        ) in result:
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
