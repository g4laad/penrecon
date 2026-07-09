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
    return [name for _id, name in host_hostnames(session, host_id)]


def host_hostnames(session: Session, host_id: int) -> list[tuple[int, str]]:
    """(hostname_id, name) for a host, excluding manually-hidden links."""
    rows = session.exec(
        select(Hostname.id, Hostname.name)
        .join(HostHostname, HostHostname.hostname_id == Hostname.id)  # type: ignore[arg-type]
        .where(HostHostname.host_id == host_id, HostHostname.hidden == False)  # noqa: E712
        .order_by(Hostname.name)
    ).all()
    return [(hid, name) for hid, name in rows if hid is not None]


def resolved_services(session: Session, host_id: int) -> list[ServiceView]:
    """Current services for display: manual overrides win over the latest
    observation, hidden services excluded, manual-only services included."""
    latest = latest_observations(session, host_id)
    views: list[ServiceView] = []
    for svc in session.exec(
        select(Service).where(Service.host_id == host_id).order_by(Service.port)  # type: ignore[arg-type]
    ).all():
        assert svc.id is not None
        o = latest.get((svc.port, svc.proto))
        state = svc.m_state or (o.state if o else None) or "unknown"
        views.append(
            ServiceView(
                service_id=svc.id,
                port=svc.port,
                proto=svc.proto,
                state=state,
                service_name=svc.m_service_name or (o.service_name if o else None),
                product=svc.m_product or (o.product if o else None),
                version=svc.m_version or (o.version if o else None),
                last_seen=(o.observed_at.strftime("%Y-%m-%d %H:%M") if o else ""),
                annotation=get_annotation(session, TargetType.service, svc.id),
                manual=o is None
                or any((svc.m_state, svc.m_service_name, svc.m_product, svc.m_version)),
            )
        )
    return views


def host_change(
    session: Session, host_id: int, *, scan_count: int, latest_scan_id: int | None
) -> str:
    """Scan-delta marker for the hosts list: ``"new"`` if the host appeared for
    the first time *in the latest scan* (and a prior baseline exists),
    ``"changed"`` if its two most-recent scans added or altered a service, else
    ``""``. Compares the host's own two latest scans (robust to partial scans),
    mirroring :func:`diff_scans`. Removals are out of scope (they live on
    /diff); manual data carries no observation and never flags.

    "new" needs a baseline: a single-scan database has nothing to be new
    *relative to*, so on the first ingest no host flags — a green column where
    everything is new says nothing. A host seen only in an older scan (absent
    from the latest) is stale, not new, so it doesn't flag either.
    # ponytail: one observation fetch per host, fine for single-user local.
    """
    obs = session.exec(
        select(Observation)
        .where(Observation.host_id == host_id)
        .order_by(
            Observation.observed_at.desc(),  # type: ignore[attr-defined]
            Observation.scan_id.desc(),  # type: ignore[attr-defined]
        )
    ).all()
    if not obs:
        return ""
    scan_order: list[int] = []
    for o in obs:
        if o.scan_id not in scan_order:
            scan_order.append(o.scan_id)
    if len(scan_order) == 1:
        # first-seen only counts as "new" against a baseline, and only if that
        # sighting is the current scan (not a host that dropped out of later scans)
        return "new" if scan_count > 1 and scan_order[0] == latest_scan_id else ""
    latest, prev = scan_order[0], scan_order[1]
    prev_obs = {(o.port, o.proto): o for o in obs if o.scan_id == prev}
    for o in obs:
        if o.scan_id != latest:
            continue
        po = prev_obs.get((o.port, o.proto))
        if po is None or _summary(o) != _summary(po):  # added or changed
            return "changed"
    return ""


def host_rows(session: Session) -> list[HostRow]:
    # scan baseline for the "new" marker: how many scans exist, and which is latest
    scan_ids = session.exec(
        select(Scan.id).order_by(Scan.imported_at.desc())  # type: ignore[attr-defined]
    ).all()
    scan_count = len(scan_ids)
    latest_scan_id = scan_ids[0] if scan_ids else None
    rows: list[HostRow] = []
    for host in session.exec(select(Host).order_by(Host.ip)).all():
        assert host.id is not None
        open_s = [s for s in resolved_services(session, host.id) if s.state == "open"]
        ann = get_annotation(session, TargetType.host, host.id)
        rows.append(
            HostRow(
                id=host.id,
                ip=host.ip,
                hostnames=_hostnames_for(session, host.id),
                open_count=len(open_s),
                status=(ann.status if ann else Status.new),
                tags=(ann.tags if ann else []),
                open_ports=sorted(s.port for s in open_s),
                service_names=sorted({s.service_name for s in open_s if s.service_name}),
                open_services=sorted((s.port, s.service_name) for s in open_s),
                change=host_change(
                    session, host.id, scan_count=scan_count, latest_scan_id=latest_scan_id
                ),
                triaged=ann is not None,
            )
        )
    return rows


def filter_hosts(
    rows: list[HostRow],
    q: str = "",
    port: int | None = None,
    tag: str = "",
    status: str = "",
    change: str = "",
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
    if change:  # "new" | "changed" — isolate what moved since the last scan
        out = [r for r in out if r.change == change]
    return out


SORT_DEFAULT_DIR = {"ports": "desc", "ip": "asc", "status": "asc"}


def sort_hosts(rows: list[HostRow], sort: str, direction: str = "") -> list[HostRow]:
    reverse = direction == "desc"
    if sort == "ports":
        return sorted(rows, key=lambda r: r.open_count, reverse=reverse)
    if sort == "status":
        return sorted(rows, key=lambda r: r.status, reverse=reverse)

    def ip_key(r: HostRow) -> tuple[int, ...]:
        parts = r.ip.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return tuple(int(p) for p in parts)
        return (999, 999, 999, 999)  # non-IPv4 sorts last

    return sorted(rows, key=ip_key, reverse=reverse)


def host_services(session: Session, host_id: int) -> list[ServiceView]:
    return resolved_services(session, host_id)


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
