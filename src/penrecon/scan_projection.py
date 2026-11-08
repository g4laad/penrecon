"""Rebuild persisted scan histories and scan-only current state."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from typing import TYPE_CHECKING

from pydantic import TypeAdapter
from sqlalchemy import case, delete, false, func, insert, update
from sqlmodel import Session, col, select

if TYPE_CHECKING:
    from penrecon.history import TimelineEntry
    from penrecon.models import Host, Scan


@cache
def timeline_adapter() -> TypeAdapter[TimelineEntry]:
    from penrecon.history import TimelineEntry

    return TypeAdapter(TimelineEntry)


@dataclass
class ReplayScope:
    hosts: set[int] = field(default_factory=set)
    new_hosts: dict[int, Host] = field(default_factory=dict)
    scans: dict[int, Scan] = field(default_factory=dict)
    deleted_scans: set[int] = field(default_factory=set)
    full: bool = False

    def merge(self, other: ReplayScope) -> None:
        self.hosts.update(other.hosts)
        self.new_hosts.update(other.new_hosts)
        self.scans.update(other.scans)
        self.deleted_scans.update(other.deleted_scans)
        self.full |= other.full

    def copy(self) -> ReplayScope:
        return ReplayScope(
            set(self.hosts),
            dict(self.new_hosts),
            dict(self.scans),
            set(self.deleted_scans),
            self.full,
        )


def rebuild_engagement(
    session: Session,
    engagement_id: str,
    scope: ReplayScope | None = None,
) -> None:
    from penrecon.history import ReplayInputs, rebuild_history
    from penrecon.inventory import normalize_ip
    from penrecon.models import (
        Host,
        HostScanDelta,
        HostScanState,
        Scan,
        ScanEvidenceComplete,
    )

    host_ids: set[int] | None = None
    if scope is not None and not scope.full:
        scan_ids = {
            scan.id
            for scan in scope.scans.values()
            if scan.id is not None and scan.id not in scope.deleted_scans
        }
        complete = (
            set(
                session.execute(
                    select(ScanEvidenceComplete.scan_id).where(
                        ScanEvidenceComplete.engagement_id == engagement_id,
                        col(ScanEvidenceComplete.scan_id).in_(scan_ids),
                    )
                ).scalars()
            )
            if scan_ids
            else set()
        )
        if scan_ids <= complete:
            host_ids = set(scope.hosts)
            host_ids.update(
                host.id for host in scope.new_hosts.values() if host.id is not None
            )
            if scan_ids:
                # Scan metadata edits affect its existing histories even when
                # evidence itself was not changed in this transaction.
                host_ids.update(
                    session.execute(
                        select(HostScanDelta.host_id).where(
                            HostScanDelta.engagement_id == engagement_id,
                            col(HostScanDelta.scan_id).in_(scan_ids),
                        )
                    ).scalars()
                )
            # Legacy aliases are separate identities, but evidence attribution
            # can affect the raw fallback of a canonical sibling.
            identities = list(
                session.execute(
                    select(Host.id, Host.ip).where(Host.engagement_id == engagement_id)
                )
            )
            canonical: dict[int, str] = {}
            for identity, ip in identities:
                if identity is not None:
                    try:
                        canonical[identity] = normalize_ip(ip)
                    except ValueError:
                        continue
            affected_ips = {
                canonical[identity] for identity in host_ids if identity in canonical
            }
            host_ids.update(
                identity for identity, ip in canonical.items() if ip in affected_ips
            )

    scan_ids_ordered = list(
        session.execute(
            select(Scan.id)
            .where(Scan.engagement_id == engagement_id)
            .order_by(col(Scan.imported_at).desc())
        ).scalars()
    )
    latest_scan_id = scan_ids_ordered[0] if scan_ids_ordered else None
    host_filter = [col(Host.engagement_id) == engagement_id]
    state_filter = [col(HostScanState.engagement_id) == engagement_id]
    delta_filter = [col(HostScanDelta.engagement_id) == engagement_id]
    if host_ids is not None:
        host_filter.append(col(Host.id).in_(host_ids))
        state_filter.append(col(HostScanState.host_id).in_(host_ids))
        delta_filter.append(col(HostScanDelta.host_id).in_(host_ids))
    states = {
        row.host_id: row
        for row in session.execute(select(HostScanState).where(*state_filter)).scalars()
    }
    session.execute(delete(HostScanDelta).where(*delta_filter))
    hosts = session.execute(select(Host).where(*host_filter)).scalars().all()
    inputs = ReplayInputs.load(session, engagement_id=engagement_id, host_ids=host_ids)
    adapter = timeline_adapter()
    for host in hosts:
        assert host.id is not None
        entries, latest = rebuild_history(
            session,
            host.id,
            engagement_id=engagement_id,
            inputs=inputs,
        )
        change = ""
        if len(entries) == 1:
            if len(scan_ids_ordered) > 1 and entries[0].scan_id == latest_scan_id:
                change = "new"
        elif entries and entries[-1].changes:
            change = "changed"
        state = states.get(host.id)
        if state is None:
            state = HostScanState(engagement_id=engagement_id, host_id=host.id)
        state.latest = [row.model_dump(mode="json") for row in latest.values()]
        state.change = change
        session.add(state)
        if entries:
            session.execute(
                insert(HostScanDelta),
                [
                    {
                        "engagement_id": engagement_id,
                        "host_id": host.id,
                        "scan_id": entry.scan_id,
                        "entry": adapter.dump_python(entry, mode="json"),
                    }
                    for entry in entries
                ],
            )
    session.flush()
    # "New" is engagement-relative, unlike historical deltas. Refresh its
    # scalar marker without replaying hosts absent from the changed scan.
    new_hosts = (
        select(HostScanDelta.host_id)
        .where(
            HostScanDelta.engagement_id == engagement_id,
        )
        .group_by(col(HostScanDelta.host_id))
        .having(
            func.count() == 1,
            func.min(HostScanDelta.scan_id) == latest_scan_id,
        )
    )
    new_marker = (
        col(HostScanState.host_id).in_(new_hosts)
        if len(scan_ids_ordered) > 1
        else false()
    )
    marker = case(
        (new_marker, "new"),
        (col(HostScanState.change) == "new", ""),
        else_=col(HostScanState.change),
    )
    session.execute(
        update(HostScanState)
        .where(
            col(HostScanState.engagement_id) == engagement_id,
            col(HostScanState.change) != marker,
        )
        .values(change=marker)
        .execution_options(synchronize_session="fetch")
    )
