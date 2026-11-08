from __future__ import annotations

from dataclasses import dataclass, field

from sqlmodel import Session, select

from penrecon.models import Host, Observation, Scan
from penrecon.queries.ownership import get_owned


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
