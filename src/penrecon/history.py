"""Scan-only history and a unified host timeline of scans and manual actions.

Reads use persisted projections. The write-side reducer applies aggregate
evidence only to ports already known at that point in history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import func
from sqlmodel import Session, col, select

from penrecon.db import DATA_DIR
from penrecon.inventory import normalize_ip
from penrecon.models import (
    Host,
    HostScanDelta,
    HostScanEvidence,
    HostTimelineEntry,
    ManualServiceEvent,
    Observation,
    ObsState,
    Scan,
    ScanEvidenceComplete,
)
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
    cache: dict[tuple[int | None, str | None, str], list[HostResult] | None] = (
        session.info.setdefault("timeline_raw", {})
    )
    if key not in cache:
        result = None
        if scan.raw_path:
            try:
                path = Path(scan.raw_path)
                path = path if path.is_absolute() else DATA_DIR / path
                result = get_parser(scan.tool)(path.read_bytes())
            except OSError, ValueError:
                # Missing/corrupt legacy raw is not evidence of closure or of
                # absence. Existing observations remain usable below.
                pass
        cache[key] = result
    return cache[key]


@dataclass
class ReplayInputs:
    """One engagement's write-side replay sources, indexed once per rebuild.

    Selected hosts limit evidence payloads, not durable attribution: equivalent
    sibling identities must still retain ownership of their historical scans.
    Instances are snapshots and must not be reused after source mutations.
    """

    engagement_id: str
    _evidence_by_host: dict[int, list[_Evidence]]

    @classmethod
    def load(
        cls,
        session: Session,
        *,
        engagement_id: str,
        host_ids: set[int] | None = None,
    ) -> ReplayInputs:
        canonical_by_host: dict[int, str] = {}
        selected_hosts: set[int] = set()
        selected_by_ip: dict[str, list[int]] = {}
        for host_id, ip in session.exec(
            select(Host.id, Host.ip).where(Host.engagement_id == engagement_id)
        ).all():
            assert host_id is not None
            selected = host_ids is None or host_id in host_ids
            if selected:
                selected_hosts.add(host_id)
            try:
                canonical = normalize_ip(ip)
            except ValueError:
                # Malformed legacy identities still retain durable evidence and
                # observations, but never matched raw recovery via same_ip.
                continue
            canonical_by_host[host_id] = canonical
            if selected:
                selected_by_ip.setdefault(canonical, []).append(host_id)
        if not selected_hosts:
            return cls(engagement_id, {})

        scans: dict[int, Scan] = {}
        for scan in session.exec(
            select(Scan).where(Scan.engagement_id == engagement_id)
        ).all():
            assert scan.id is not None
            scans[scan.id] = scan
        complete = set(
            session.exec(
                select(ScanEvidenceComplete.scan_id).where(
                    ScanEvidenceComplete.engagement_id == engagement_id,
                )
            ).all()
        )
        attributed: set[tuple[int, str]] = set()
        for scan_id, host_id in session.exec(
            select(HostScanEvidence.scan_id, HostScanEvidence.host_id).where(
                HostScanEvidence.engagement_id == engagement_id,
            )
        ).all():
            attributed_ip = canonical_by_host.get(host_id)
            if attributed_ip is not None:
                attributed.add((scan_id, attributed_ip))

        durable_query = select(HostScanEvidence).where(
            HostScanEvidence.engagement_id == engagement_id,
        )
        observations_query = select(Observation).where(
            Observation.engagement_id == engagement_id,
        )
        if host_ids is not None:
            durable_query = durable_query.where(
                col(HostScanEvidence.host_id).in_(selected_hosts)
            )
            observations_query = observations_query.where(
                col(Observation.host_id).in_(selected_hosts)
            )
        by_host: dict[int, dict[int, _Evidence]] = {}

        def store(
            host_id: int,
            scan_id: int,
            scanned_at: datetime | None,
            coverage: dict[str, Any],
            ports: list[dict[str, Any]],
        ) -> None:
            scan = scans.get(scan_id)
            if scan is not None and host_id in selected_hosts:
                by_host.setdefault(host_id, {})[scan_id] = _Evidence(
                    scan=scan,
                    occurred_at=_utc(scanned_at or scan.imported_at),
                    time_source="scan" if scanned_at is not None else "import",
                    coverage=coverage,
                    ports=ports,
                )

        durable: set[tuple[int, int]] = set()
        for row in session.exec(durable_query).all():
            durable.add((row.host_id, row.scan_id))
            store(row.host_id, row.scan_id, row.scanned_at, row.coverage, row.ports)
        observations: dict[tuple[int, int], list[dict[str, Any]]] = {}
        for observation in session.exec(observations_query).all():
            if (observation.host_id, observation.scan_id) not in durable:
                observations.setdefault(
                    (observation.host_id, observation.scan_id), []
                ).append(
                    {
                        "port": observation.port,
                        "proto": observation.proto,
                        "state": str(observation.state),
                        "service_name": observation.service_name,
                        "product": observation.product,
                        "version": observation.version,
                        "extra": observation.extra,
                    }
                )
        for (host_id, scan_id), ports in observations.items():
            # Observations remain usable even on complete scans without a
            # durable host row. Only raw recovery is ruled out by completeness.
            store(host_id, scan_id, None, {}, ports)
        for scan_id, scan in scans.items():
            assert scan_id is not None
            if scan_id in complete:
                continue
            recovered_ips: set[str] = set()
            for recovered in _raw_hosts(session, scan) or []:
                try:
                    canonical = normalize_ip(recovered.ip)
                except ValueError:
                    continue
                if canonical in recovered_ips:
                    continue
                recovered_ips.add(canonical)
                if (scan_id, canonical) in attributed:
                    continue
                matching = selected_by_ip.get(canonical, [])
                if matching:
                    ports = [vars(port).copy() for port in recovered.ports]
                    for host_id in matching:
                        store(
                            host_id,
                            scan_id,
                            recovered.scanned_at,
                            recovered.coverage,
                            ports,
                        )
        return cls(
            engagement_id,
            {
                host_id: sorted(
                    evidence.values(),
                    key=lambda row: (
                        row.occurred_at,
                        _utc(row.scan.imported_at),
                        row.scan.id or 0,
                    ),
                )
                for host_id, evidence in by_host.items()
            },
        )


def _aggregate_state(coverage: dict[str, Any], port: int, proto: str) -> str | None:
    states = {
        group["state"]
        for group in coverage.get("states", [])
        if group.get("proto") == proto
        and group.get("state") in {"closed", "filtered"}
        and any(start <= port <= end for start, end in group.get("ports", []))
    }
    return next(iter(states)) if len(states) == 1 else None


@dataclass(frozen=True)
class _PortTransition:
    evidence: Literal["missing", "covered", "explicit"]
    after: State | None
    extra: dict[str, Any] = field(default_factory=dict)


def _reduce_port_evidence(
    before: State | None,
    explicit: dict[str, Any] | None,
    coverage: dict[str, Any],
    port: int,
    proto: str,
) -> _PortTransition:
    """Resolve one replay step without inventing observations from omission.

    Explicit evidence replaces all observed details. Unambiguous coverage can
    change only a known port's state, retaining its identity details. Missing
    evidence leaves both the baseline and its latest observation untouched.
    """
    if explicit is not None:
        return _PortTransition(
            "explicit",
            State(
                str(explicit["state"]),
                explicit.get("service_name"),
                explicit.get("product"),
                explicit.get("version"),
            ),
            explicit.get("extra", {}),
        )
    covered_state = _aggregate_state(coverage, port, proto)
    if before is not None and covered_state is not None:
        return _PortTransition(
            "covered",
            State(covered_state, before.service_name, before.product, before.version),
        )
    return _PortTransition("missing", before)


def rebuild_history(
    session: Session,
    host_id: int,
    *,
    engagement_id: str,
    inputs: ReplayInputs | None = None,
) -> tuple[list[TimelineEntry], dict[tuple[int, str], Observation]]:
    """Write-side replay: oldest-first comparisons and latest scan-only state.

    Only projection maintenance calls this reducer. A partial scan leaves the
    last known state intact, and never resets a port baseline. Observations can
    represent virtual aggregate evidence rather than stored rows.
    """
    if inputs is None:
        inputs = ReplayInputs.load(
            session, engagement_id=engagement_id, host_ids={host_id}
        )
    elif inputs.engagement_id != engagement_id:
        raise ValueError("Replay inputs belong to a different engagement")
    entries: list[TimelineEntry] = []
    known: dict[tuple[int, str], State] = {}
    latest: dict[tuple[int, str], Observation] = {}
    for evidence in inputs._evidence_by_host.get(host_id, []):
        scan = evidence.scan
        assert scan.id is not None
        explicit = {
            (int(row["port"]), str(row["proto"])): row for row in evidence.ports
        }
        # Reduce only already-known identities and explicit reports. Coverage is
        # never an instruction to manufacture every port in its ranges.
        entry = TimelineEntry(
            id=f"scan:{scan.id}",
            source="scan",
            scan_id=scan.id,
            filename=scan.filename,
            tool=scan.tool,
            occurred_at=evidence.occurred_at.isoformat(),
            imported_at=_utc(scan.imported_at).isoformat(),
            time_source=evidence.time_source,
            first_seen=not entries,
            coverage_known=bool(evidence.coverage.get("known")),
            not_reported=[],
        )
        for port, proto in sorted(known.keys() | explicit.keys()):
            before = known.get((port, proto))
            transition = _reduce_port_evidence(
                before,
                explicit.get((port, proto)),
                evidence.coverage,
                port,
                proto,
            )
            if transition.evidence == "missing":
                entry.not_reported.append(PortIdentity(port, proto))
                continue
            after = transition.after
            assert after is not None
            if before != after:
                entry.changes.append(
                    Change(
                        port,
                        proto,
                        "added" if before is None else "changed",
                        before,
                        after,
                    )
                )
            known[(port, proto)] = after
            latest[(port, proto)] = Observation(
                engagement_id=engagement_id,
                scan_id=scan.id,
                host_id=host_id,
                port=port,
                proto=proto,
                state=ObsState(after.state),
                service_name=after.service_name,
                product=after.product,
                version=after.version,
                extra=transition.extra,
                observed_at=evidence.occurred_at,
            )
        entries.append(entry)
    return entries, latest


def host_history(
    session: Session,
    host_id: int,
    *,
    engagement_id: str,
) -> tuple[list[TimelineEntry], dict[tuple[int, str], Observation]]:
    """Read persisted oldest-first scan comparisons and scan-only current state."""
    from penrecon.projections import scan_history

    return scan_history(session, host_id, engagement_id=engagement_id)


def _snapshot_state(snapshot: dict[str, str | None] | None) -> State | None:
    if snapshot is None:
        return None
    state = snapshot["state"]
    assert state is not None
    return State(
        state,
        snapshot.get("service_name"),
        snapshot.get("product"),
        snapshot.get("version"),
    )


def timeline(
    session: Session,
    host_id: int,
    *,
    engagement_id: str,
    page: int = 1,
    show_unchanged: bool = False,
) -> HostTimeline:
    """Page indexed timeline metadata, then load only the selected payloads."""
    from penrecon.projections import prepare_read
    from penrecon.scan_projection import timeline_adapter

    prepare_read(session)
    scope = (
        col(HostTimelineEntry.engagement_id) == engagement_id,
        col(HostTimelineEntry.host_id) == host_id,
    )
    changed_scope = (*scope, col(HostTimelineEntry.changed) == True)
    visible_scope = scope if show_unchanged else changed_scope
    total = session.execute(
        select(func.count()).select_from(HostTimelineEntry).where(*visible_scope),
    ).scalar_one()
    pages = max(1, (total + 19) // 20)
    page = max(1, min(page, pages))
    ordering = (
        col(HostTimelineEntry.occurred_at).desc(),
        col(HostTimelineEntry.imported_at).desc(),
        col(HostTimelineEntry.source).desc(),
        col(HostTimelineEntry.source_id).desc(),
    )
    candidates = select(HostTimelineEntry.source, HostTimelineEntry.source_id)
    selected = session.execute(
        candidates.where(*visible_scope)
        .order_by(*ordering)
        .limit(20)
        .offset((page - 1) * 20),
    ).all()
    latest = session.execute(
        candidates.where(*changed_scope).order_by(*ordering).limit(1),
    ).first()
    wanted = set(selected)
    if latest is not None:
        wanted.add(latest)
    entries: dict[tuple[str, int], TimelineEntry] = {}
    scan_ids = [row_id for source, row_id in wanted if source == "scan"]
    if scan_ids:
        adapter = timeline_adapter()
        for scan_id, payload in session.exec(
            select(HostScanDelta.scan_id, HostScanDelta.entry).where(
                HostScanDelta.engagement_id == engagement_id,
                HostScanDelta.host_id == host_id,
                col(HostScanDelta.scan_id).in_(scan_ids),
            )
        ).all():
            entries[("scan", scan_id)] = adapter.validate_python(payload)
    manual_ids = [row_id for source, row_id in wanted if source == "manual"]
    if manual_ids:
        for event in session.exec(
            select(ManualServiceEvent).where(
                ManualServiceEvent.engagement_id == engagement_id,
                ManualServiceEvent.host_id == host_id,
                col(ManualServiceEvent.id).in_(manual_ids),
            )
        ).all():
            assert event.id is not None
            occurred_at = _utc(event.occurred_at).isoformat()
            entries[("manual", event.id)] = TimelineEntry(
                id=f"manual:{event.id}",
                source="manual",
                scan_id=None,
                filename="",
                tool="",
                occurred_at=occurred_at,
                imported_at=occurred_at,
                time_source="manual",
                first_seen=False,
                coverage_known=False,
                changes=[
                    Change(
                        port=event.port,
                        proto=event.proto,
                        kind=event.kind,
                        before=_snapshot_state(event.before),
                        after=_snapshot_state(event.after),
                        before_overrides=Overrides(**event.before_overrides)
                        if event.before_overrides is not None
                        else None,
                        after_overrides=Overrides(**event.after_overrides)
                        if event.after_overrides is not None
                        else None,
                    )
                ],
            )
    return HostTimeline(
        [entries[(source, row_id)] for source, row_id in selected],
        total,
        page,
        pages,
        show_unchanged,
        entries[(latest[0], latest[1])] if latest is not None else None,
    )
