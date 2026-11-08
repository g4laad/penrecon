"""Rebuild indexed timeline metadata without copying persisted event payloads."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, insert
from sqlmodel import Session, col, select


def _utc(value: str | datetime) -> datetime:
    timestamp = datetime.fromisoformat(value) if isinstance(value, str) else value
    timestamp = timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp.astimezone(UTC)
    return timestamp.replace(tzinfo=None)


def rebuild_timeline(session: Session, engagement_id: str) -> None:
    """Replace one engagement's metadata from its existing scan/manual history."""
    from penrecon.models import HostScanDelta, HostTimelineEntry, ManualServiceEvent

    session.execute(delete(HostTimelineEntry).where(
        col(HostTimelineEntry.engagement_id) == engagement_id,
    ))
    rows: list[dict[str, Any]] = []
    for host_id, scan_id, entry in session.execute(
        select(HostScanDelta.host_id, HostScanDelta.scan_id, HostScanDelta.entry).where(
            HostScanDelta.engagement_id == engagement_id,
        )
    ):
        rows.append({
            "engagement_id": engagement_id,
            "host_id": host_id,
            "source": "scan",
            "source_id": scan_id,
            "occurred_at": _utc(entry["occurred_at"]),
            "imported_at": _utc(entry["imported_at"]),
            "changed": bool(entry["first_seen"] or entry["changes"]),
        })
        if len(rows) == 500:
            session.execute(insert(HostTimelineEntry), rows)
            rows.clear()
    for host_id, event_id, occurred_at in session.execute(
        select(ManualServiceEvent.host_id, ManualServiceEvent.id, ManualServiceEvent.occurred_at).where(
            ManualServiceEvent.engagement_id == engagement_id,
        )
    ):
        timestamp = _utc(occurred_at)
        rows.append({
            "engagement_id": engagement_id,
            "host_id": host_id,
            "source": "manual",
            "source_id": event_id,
            "occurred_at": timestamp,
            "imported_at": timestamp,
            "changed": True,
        })
        if len(rows) == 500:
            session.execute(insert(HostTimelineEntry), rows)
            rows.clear()
    if rows:
        session.execute(insert(HostTimelineEntry), rows)
