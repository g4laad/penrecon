"""Transactional scan projections, rebuilt only when evidence is written.

The original history reducer is the single source of merge semantics. Evidence
writes invalidate their whole engagement, including global first-sighting markers;
steady reads deserialize current state and deltas without recovering raw scans.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any

from pydantic import TypeAdapter
from sqlalchemy import delete, event, inspect, insert
from sqlalchemy.orm import SessionTransaction
from sqlmodel import Session, col, select


if TYPE_CHECKING:
    from penrecon.history import TimelineEntry
    from penrecon.models import Host, HostScanEvidence, Observation, Scan

_PENDING = "scan_projection_pending"
_REBUILDING = "scan_projection_rebuilding"
_SAVEPOINTS = "scan_projection_savepoints"


@cache
def _evidence_types() -> tuple[type[Scan], type[Host], type[HostScanEvidence], type[Observation]]:
    from penrecon.models import Host, HostScanEvidence, Observation, Scan

    return Scan, Host, HostScanEvidence, Observation


@cache
def _timeline_adapter() -> TypeAdapter[TimelineEntry]:
    from penrecon.history import TimelineEntry

    return TypeAdapter(TimelineEntry)


def _pending(session: Session) -> set[str]:
    return session.info.setdefault(_PENDING, set())  # type: ignore[no-any-return]


def _savepoints(session: Session) -> dict[SessionTransaction, set[str]]:
    return session.info.setdefault(_SAVEPOINTS, {})  # type: ignore[no-any-return]


def _has_evidence_changes(session: Session) -> bool:
    return any(
        isinstance(row, _evidence_types())
        for rows in (session.new, session.dirty, session.deleted)
        for row in rows
    )


def _collect(session: Session, _flush_context: Any, _instances: Any) -> None:
    if session.info.get(_REBUILDING):
        return
    _collect_evidence(session)


def _rebuild_engagement(session: Session, engagement_id: str) -> None:
    from penrecon.history import rebuild_history
    from penrecon.models import Host, HostScanDelta, HostScanState, Scan

    scan_ids = list(session.execute(
        select(Scan.id).where(Scan.engagement_id == engagement_id)
        .order_by(col(Scan.imported_at).desc())
    ).scalars())
    latest_scan_id = scan_ids[0] if scan_ids else None
    states = {
        row.host_id: row for row in session.execute(
            select(HostScanState).where(HostScanState.engagement_id == engagement_id)
        ).scalars()
    }
    session.execute(delete(HostScanDelta).where(
        col(HostScanDelta.engagement_id) == engagement_id,
    ))
    hosts = session.execute(select(Host).where(Host.engagement_id == engagement_id)).scalars().all()
    adapter = _timeline_adapter()
    for host in hosts:
        assert host.id is not None
        entries, latest = rebuild_history(session, host.id, engagement_id=engagement_id)
        change = ""
        if len(entries) == 1:
            if len(scan_ids) > 1 and entries[0].scan_id == latest_scan_id:
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
            session.execute(insert(HostScanDelta), [
                {
                    "engagement_id": engagement_id,
                    "host_id": host.id,
                    "scan_id": entry.scan_id,
                    "entry": adapter.dump_python(entry, mode="json"),
                }
                for entry in entries
            ])


def prepare_read(session: Session) -> None:
    """Project only pending evidence writes belonging to this session.

    Explicit flushes (including fixtures) only collect scopes. This seam and
    before_commit finish their projections after the complete evidence is staged.
    It is a no-op for steady reads and for manual-only writes.
    """
    if session.info.get(_REBUILDING):
        return
    if not session.info.get(_PENDING) and not _has_evidence_changes(session):
        return
    session.info[_REBUILDING] = True
    scopes: set[str] = set()
    try:
        # Flush can assign host IDs and cascade evidence deletion; projection
        # queries must see all of it, without collecting projection writes.
        _collect_evidence(session)
        session.flush()
        scopes = session.info.pop(_PENDING, set())
        session.info.pop("timeline_raw", None)
        for engagement_id in sorted(scopes):
            _rebuild_engagement(session, engagement_id)
        session.flush()
    except BaseException:
        if session.is_active:
            # A reducer/serialization error need not fail the DB transaction.
            # Retain invalidation so a retry cannot commit stale projections.
            _pending(session).update(scopes)
        else:
            session.info.pop(_PENDING, None)
        raise
    finally:
        session.info.pop(_REBUILDING, None)
        session.info.pop("timeline_raw", None)


def _collect_evidence(session: Session) -> None:
    # This explicit collector also runs while the rebuild guard suppresses the
    # before_flush hook. No evidence is changed by the projection itself.
    scopes = _pending(session)
    for rows in (session.new, session.dirty, session.deleted):
        for row in rows:
            if isinstance(row, _evidence_types()):
                scopes.add(row.engagement_id)
                state = inspect(row)
                assert state is not None
                scopes.update(state.attrs.engagement_id.history.deleted)


def latest_for_host(
    session: Session, host_id: int, *, engagement_id: str,
) -> dict[tuple[int, str], Observation]:
    from penrecon.models import HostScanState, Observation

    prepare_read(session)
    row = session.execute(select(HostScanState).where(
        HostScanState.engagement_id == engagement_id, HostScanState.host_id == host_id,
    )).scalar_one_or_none()
    if row is None:
        return {}
    observations = [Observation.model_validate(value) for value in row.latest]
    return {(value.port, value.proto): value for value in observations}


def scan_history(
    session: Session, host_id: int, *, engagement_id: str,
) -> tuple[list[TimelineEntry], dict[tuple[int, str], Observation]]:
    from penrecon.models import HostScanDelta

    latest = latest_for_host(session, host_id, engagement_id=engagement_id)
    adapter = _timeline_adapter()
    entries = [
        adapter.validate_python(value) for value in session.execute(
            select(HostScanDelta.entry).where(
                HostScanDelta.engagement_id == engagement_id, HostScanDelta.host_id == host_id,
            )
        ).scalars()
    ]
    entries.sort(key=lambda entry: (
        entry.occurred_at, entry.imported_at, entry.scan_id or 0,
    ))
    return entries, latest


def backfill_missing(session: Session) -> None:
    """Populate additive tables for legacy hosts, without changing evidence.

    An empty state row is meaningful: even a manual-only host has been projected.
    A repeat startup with complete projections never invokes the history reducer.
    """
    from penrecon.models import Host, HostScanState

    scopes = session.execute(
        select(Host.engagement_id).outerjoin(
            HostScanState,
            (col(HostScanState.host_id) == col(Host.id))
            & (col(HostScanState.engagement_id) == col(Host.engagement_id)),
        ).where(col(HostScanState.host_id).is_(None)).distinct()
    ).scalars().all()
    if not scopes:
        return
    session.info[_REBUILDING] = True
    try:
        session.info.pop("timeline_raw", None)
        for engagement_id in scopes:
            _rebuild_engagement(session, engagement_id)
        session.flush()
    finally:
        session.info.pop(_REBUILDING, None)
        session.info.pop("timeline_raw", None)


def _before_commit(session: Session) -> None:
    prepare_read(session)


def _after_transaction_create(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        # begin_nested flushes outer evidence before creating the savepoint. If a
        # read consumes it inside this savepoint, rollback must make it pending
        # again because the projection writes will also have been rolled back.
        _savepoints(session)[transaction] = set(_pending(session))


def _clear(session: Session) -> None:
    session.info.pop(_PENDING, None)
    session.info.pop(_SAVEPOINTS, None)
    session.info.pop("timeline_raw", None)


def _after_commit(session: Session) -> None:
    nested = session.get_nested_transaction()
    if nested is not None:
        _savepoints(session).pop(nested, None)
    else:
        _clear(session)


def _after_rollback(session: Session) -> None:
    if not session.in_nested_transaction():
        _clear(session)


def _after_soft_rollback(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        session.info[_PENDING] = _savepoints(session).pop(transaction, set())
        session.info.pop("timeline_raw", None)
    elif transaction.parent is None:
        _clear(session)


def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:
    if transaction.parent is None:
        _clear(session)


def register_session_hooks() -> None:
    """Install once for SQLModel sessions, independently of engine factories."""
    if event.contains(Session, "before_flush", _collect):
        return
    event.listen(Session, "before_flush", _collect)
    event.listen(Session, "before_commit", _before_commit)
    event.listen(Session, "after_transaction_create", _after_transaction_create)
    event.listen(Session, "after_commit", _after_commit)
    event.listen(Session, "after_rollback", _after_rollback)
    event.listen(Session, "after_soft_rollback", _after_soft_rollback)
    event.listen(Session, "after_transaction_end", _after_transaction_end)
