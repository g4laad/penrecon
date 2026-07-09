"""Read-side helpers: current-state merge, host listing/detail, scan diff,
and annotation/attachment access.

Scale note: current-state is computed in Python (latest-observation-wins).
# ponytail: naive per-host dedupe, fine for single-user local; push into SQL
# window functions if a project ever holds huge scan history.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlmodel import Session, select

from penrecon.models import (
    Annotation,
    Attachment,
    Host,
    Hostname,
    HostHostname,
    Observation,
    Scan,
    Service,
    Status,
    TargetType,
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


# --- annotations / attachments -------------------------------------------------

def get_annotation(
    session: Session, target_type: TargetType, target_id: int
) -> Annotation | None:
    return session.exec(
        select(Annotation).where(
            Annotation.target_type == target_type, Annotation.target_id == target_id
        )
    ).first()


def attachments_for(
    session: Session, target_type: TargetType, target_id: int
) -> list[Attachment]:
    return list(
        session.exec(
            select(Attachment).where(
                Attachment.target_type == target_type,
                Attachment.target_id == target_id,
            )
        ).all()
    )


# --- current-state merge -------------------------------------------------------

def latest_observations(session: Session, host_id: int) -> dict[tuple[int, str], Observation]:
    """Latest Observation per (port, proto) for one host."""
    obs = session.exec(
        select(Observation)
        .where(Observation.host_id == host_id)
        .order_by(Observation.observed_at.desc())  # type: ignore[attr-defined]
    ).all()
    latest: dict[tuple[int, str], Observation] = {}
    for o in obs:
        latest.setdefault((o.port, o.proto), o)
    return latest


def _hostnames_for(session: Session, host_id: int) -> list[str]:
    rows = session.exec(
        select(Hostname.name)
        .join(HostHostname, HostHostname.hostname_id == Hostname.id)  # type: ignore[arg-type]
        .where(HostHostname.host_id == host_id)
    ).all()
    return list(rows)


def host_rows(session: Session) -> list[HostRow]:
    rows: list[HostRow] = []
    for host in session.exec(select(Host).order_by(Host.ip)).all():
        assert host.id is not None
        latest = latest_observations(session, host.id)
        open_obs = [o for o in latest.values() if o.state == "open"]
        ann = get_annotation(session, TargetType.host, host.id)
        rows.append(
            HostRow(
                id=host.id,
                ip=host.ip,
                hostnames=_hostnames_for(session, host.id),
                open_count=len(open_obs),
                status=(ann.status if ann else Status.new),
                tags=(ann.tags if ann else []),
                open_ports=sorted(o.port for o in open_obs),
                service_names=sorted({o.service_name for o in open_obs if o.service_name}),
                open_services=sorted((o.port, o.service_name) for o in open_obs),
            )
        )
    return rows


def filter_hosts(
    rows: list[HostRow],
    q: str = "",
    port: int | None = None,
    tag: str = "",
    status: str = "",
) -> list[HostRow]:
    out = rows
    if q:
        ql = q.lower()
        out = [
            r
            for r in out
            if ql in r.ip.lower()
            or any(ql in h.lower() for h in r.hostnames)
            or any(ql in s.lower() for s in r.service_names)
        ]
    if port is not None:
        out = [r for r in out if port in r.open_ports]
    if tag:
        out = [r for r in out if tag in r.tags]
    if status:
        out = [r for r in out if r.status == status]
    return out


def sort_hosts(rows: list[HostRow], sort: str) -> list[HostRow]:
    if sort == "ports":
        return sorted(rows, key=lambda r: r.open_count, reverse=True)
    if sort == "status":
        return sorted(rows, key=lambda r: r.status)

    def ip_key(r: HostRow) -> tuple[int, ...]:
        parts = r.ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return tuple(int(p) for p in parts)
        return (999, 999, 999, 999)  # non-IPv4 sorts last

    return sorted(rows, key=ip_key)


def host_services(session: Session, host_id: int) -> list[ServiceView]:
    latest = latest_observations(session, host_id)
    views: list[ServiceView] = []
    for svc in session.exec(
        select(Service).where(Service.host_id == host_id).order_by(Service.port)  # type: ignore[arg-type]
    ).all():
        assert svc.id is not None
        o = latest.get((svc.port, svc.proto))
        views.append(
            ServiceView(
                service_id=svc.id,
                port=svc.port,
                proto=svc.proto,
                state=(o.state if o else "unknown"),
                service_name=(o.service_name if o else None),
                product=(o.product if o else None),
                version=(o.version if o else None),
                last_seen=(o.observed_at.isoformat(timespec="seconds") if o else ""),
                annotation=get_annotation(session, TargetType.service, svc.id),
            )
        )
    return views


# --- diff ----------------------------------------------------------------------

def _obs_by_key(session: Session, scan_id: int) -> dict[tuple[str, int, str], Observation]:
    stmt = (
        select(Observation, Host.ip)
        .join(Host, Host.id == Observation.host_id)  # type: ignore[arg-type]
        .where(Observation.scan_id == scan_id)
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


def diff_scans(session: Session, scan_a_id: int, scan_b_id: int) -> DiffResult:
    a = session.get(Scan, scan_a_id)
    b = session.get(Scan, scan_b_id)
    if a is None or b is None:
        raise ValueError("scan not found")
    result = DiffResult(scan_a=a, scan_b=b)
    obs_a = _obs_by_key(session, scan_a_id)
    obs_b = _obs_by_key(session, scan_b_id)

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
