"""Scan-only replay and a unified host timeline of scans and manual actions.

Neither recovery nor reads write to the database. Aggregate evidence is applied
only to ports already known at that point in history, never to every covered port.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from penrecon.db import DATA_DIR
from penrecon.models import Host, HostScanEvidence, ManualServiceEvent, Observation, Scan
from penrecon.parsers import HostResult, get_parser


@dataclass(frozen=True)
class State:
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class Overrides:
    state: str | None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class Change:
    port: int
    proto: str
    kind: str
    before: State | None
    after: State | None
    before_overrides: Overrides | None = None
    after_overrides: Overrides | None = None


@dataclass
class PortIdentity:
    port: int
    proto: str


@dataclass
class TimelineEntry:
    id: str
    source: str
    scan_id: int | None
    filename: str
    tool: str
    occurred_at: str
    imported_at: str
    time_source: str
    first_seen: bool
    coverage_known: bool
    changes: list[Change] = field(default_factory=list)
    not_reported: list[PortIdentity] = field(default_factory=list)


@dataclass
class HostTimeline:
    entries: list[TimelineEntry]
    total: int
    page: int
    pages: int
    show_unchanged: bool
    latest_change: TimelineEntry | None


@dataclass
class _Evidence:
    scan: Scan
    occurred_at: datetime
    time_source: str
    coverage: dict[str, Any]
    ports: list[dict[str, Any]]


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _raw_hosts(session: Session, scan: Scan) -> list[HostResult] | None:
    """Cache immutable raw parsing for repeated host rows within one session."""
    key = (scan.id, scan.raw_path, scan.tool)
    cache: dict[tuple[int | None, str | None, str], list[HostResult] | None] = session.info.setdefault("timeline_raw", {})
    if key not in cache:
        result = None
        if scan.raw_path:
            try:
                path = Path(scan.raw_path)
                path = path if path.is_absolute() else DATA_DIR / path
                result = get_parser(scan.tool)(path.read_bytes())
            except (OSError, ValueError):
                # Missing/corrupt legacy raw is not evidence of closure or of
                # absence. Existing observations remain usable below.
                pass
        cache[key] = result
    return cache[key]


def _evidence(session: Session, host_id: int, engagement_id: str) -> list[_Evidence]:
    host = session.exec(select(Host).where(Host.id == host_id, Host.engagement_id == engagement_id)).first()
    if host is None:
        return []
    scans = session.exec(select(Scan).where(Scan.engagement_id == engagement_id)).all()
    durable = {
        row.scan_id: row for row in session.exec(select(HostScanEvidence).where(
            HostScanEvidence.engagement_id == engagement_id, HostScanEvidence.host_id == host_id,
        )).all()
    }
    observations: dict[int, list[Observation]] = {}
    for row in session.exec(select(Observation).where(
        Observation.engagement_id == engagement_id, Observation.host_id == host_id,
    )).all():
        observations.setdefault(row.scan_id, []).append(row)
    result: list[_Evidence] = []
    for scan in scans:
        assert scan.id is not None
        stored = durable.get(scan.id)
        scanned_at: datetime | None = None
        coverage: dict[str, Any] = {}
        ports: list[dict[str, Any]]
        if stored is not None:
            scanned_at, coverage, ports = stored.scanned_at, stored.coverage, stored.ports
        else:
            raw = _raw_hosts(session, scan)
            recovered = next((row for row in raw or [] if row.ip == host.ip), None)
            if recovered is not None:
                scanned_at, coverage = recovered.scanned_at, recovered.coverage
                ports = [vars(port).copy() for port in recovered.ports]
            elif scan.id in observations:
                ports = [{
                    "port": row.port, "proto": row.proto, "state": str(row.state),
                    "service_name": row.service_name, "product": row.product,
                    "version": row.version, "extra": row.extra,
                } for row in observations[scan.id]]
            else:
                continue
        result.append(_Evidence(
            scan=scan,
            occurred_at=_utc(scanned_at or scan.imported_at),
            time_source="scan" if scanned_at is not None else "import",
            coverage=coverage,
            ports=ports,
        ))
    result.sort(key=lambda row: (row.occurred_at, _utc(row.scan.imported_at), row.scan.id or 0))
    return result


def _aggregate_state(coverage: dict[str, Any], port: int, proto: str) -> str | None:
    states = {
        group["state"] for group in coverage.get("states", [])
        if group.get("proto") == proto and group.get("state") in {"closed", "filtered"}
        and any(start <= port <= end for start, end in group.get("ports", []))
    }
    return next(iter(states)) if len(states) == 1 else None


def host_history(
    session: Session, host_id: int, *, engagement_id: str,
) -> tuple[list[TimelineEntry], dict[tuple[int, str], Observation]]:
    """Full oldest-first comparisons and latest scan-only state per port.

    All comparisons precede any visibility filtering or pagination. A partial
    scan leaves the last known state intact, and never resets a port baseline.
    Returned observations can be virtual aggregate evidence, not stored rows.
    """
    entries: list[TimelineEntry] = []
    known: dict[tuple[int, str], State] = {}
    latest: dict[tuple[int, str], Observation] = {}
    for evidence in _evidence(session, host_id, engagement_id):
        scan = evidence.scan
        assert scan.id is not None
        explicit = {(int(row["port"]), str(row["proto"])): row for row in evidence.ports}
        reported = dict(explicit)
        for port, proto in known.keys() - explicit.keys():
            state = _aggregate_state(evidence.coverage, port, proto)
            if state is not None:
                previous = known[(port, proto)]
                reported[(port, proto)] = {
                    "port": port, "proto": proto, "state": state,
                    "service_name": previous.service_name,
                    "product": previous.product, "version": previous.version,
                }
        entry = TimelineEntry(
            id=f"scan:{scan.id}", source="scan",
            scan_id=scan.id, filename=scan.filename, tool=scan.tool,
            occurred_at=evidence.occurred_at.isoformat(),
            imported_at=_utc(scan.imported_at).isoformat(), time_source=evidence.time_source,
            first_seen=not entries, coverage_known=bool(evidence.coverage.get("known")),
            not_reported=[PortIdentity(port, proto) for port, proto in sorted(known.keys() - reported.keys())],
        )
        for (port, proto), row in sorted(reported.items()):
            after = State(str(row["state"]), row.get("service_name"), row.get("product"), row.get("version"))
            before = known.get((port, proto))
            if before != after:
                entry.changes.append(Change(port, proto, "added" if before is None else "changed", before, after))
            known[(port, proto)] = after
            latest[(port, proto)] = Observation(
                engagement_id=engagement_id, scan_id=scan.id, host_id=host_id,
                port=port, proto=proto, state=after.state,
                service_name=after.service_name, product=after.product, version=after.version,
                extra=row.get("extra", {}), observed_at=evidence.occurred_at,
            )
        entries.append(entry)
    return entries, latest


def _snapshot_state(snapshot: dict[str, str | None] | None) -> State | None:
    if snapshot is None:
        return None
    state = snapshot["state"]
    assert state is not None
    return State(state, snapshot.get("service_name"), snapshot.get("product"), snapshot.get("version"))


def timeline(
    session: Session, host_id: int, *, engagement_id: str,
    page: int = 1, show_unchanged: bool = False,
) -> HostTimeline:
    """Merge immutable manual actions after scan replay, before pagination."""
    entries, _ = host_history(session, host_id, engagement_id=engagement_id)
    for event in session.exec(select(ManualServiceEvent).where(
        ManualServiceEvent.engagement_id == engagement_id,
        ManualServiceEvent.host_id == host_id,
    )).all():
        assert event.id is not None
        occurred_at = _utc(event.occurred_at).isoformat()
        entries.append(TimelineEntry(
            id=f"manual:{event.id}", source="manual", scan_id=None,
            filename="", tool="", occurred_at=occurred_at, imported_at=occurred_at,
            time_source="manual", first_seen=False, coverage_known=False,
            changes=[Change(
                port=event.port, proto=event.proto, kind=event.kind,
                before=_snapshot_state(event.before),
                after=_snapshot_state(event.after),
                before_overrides=Overrides(**event.before_overrides) if event.before_overrides is not None else None,
                after_overrides=Overrides(**event.after_overrides) if event.after_overrides is not None else None,
            )],
        ))
    entries.sort(key=lambda entry: (
        _utc(datetime.fromisoformat(entry.occurred_at)),
        _utc(datetime.fromisoformat(entry.imported_at)),
        entry.source, int(entry.id.partition(":")[2]),
    ), reverse=True)
    latest_change = next((entry for entry in entries if entry.first_seen or entry.changes), None)
    visible = [entry for entry in entries if show_unchanged or entry.first_seen or entry.changes]
    total = len(visible)
    pages = max(1, (total + 19) // 20)
    page = max(1, min(page, pages))
    return HostTimeline(visible[(page - 1) * 20:page * 20], total, page, pages, show_unchanged, latest_change)
