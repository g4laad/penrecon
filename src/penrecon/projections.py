"""Transactional scan, inventory, and timeline projections maintained on writes.

The history reducer owns scan merge semantics; service_state owns effective
manual overrides. Evidence invalidates all projections, while inventory and
timeline writes reuse persisted scan state without recovering raw scans.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any

from sqlalchemy import event, func, inspect, true
from sqlalchemy.orm import SessionTransaction
from sqlmodel import Session, col, select

from penrecon import inventory_projection, scan_projection, timeline_projection


if TYPE_CHECKING:
    from penrecon.history import TimelineEntry
    from penrecon.models import (
        Annotation, Host, Hostname, HostHostname, HostScanEvidence, Observation, Scan, Service,
    )

_PENDING = "scan_projection_pending"
_INVENTORY_PENDING = "inventory_projection_pending"
_TIMELINE_PENDING = "timeline_projection_pending"
_REBUILDING = "scan_projection_rebuilding"
_SAVEPOINTS = "scan_projection_savepoints"
_REPLAY_TARGETS = "scan_projection_targets"


@cache
def _evidence_types() -> tuple[type[Scan], type[Host], type[HostScanEvidence], type[Observation]]:
    from penrecon.models import Host, HostScanEvidence, Observation, Scan

    return Scan, Host, HostScanEvidence, Observation


@cache
def _inventory_types() -> tuple[
    type[Scan], type[Host], type[HostScanEvidence], type[Observation],
    type[Annotation], type[Hostname], type[HostHostname], type[Service],
]:
    from penrecon.models import Annotation, Hostname, HostHostname, Service

    return _evidence_types() + (Annotation, Hostname, HostHostname, Service)


@cache
def _source_types() -> tuple[type[Any], ...]:
    from penrecon.models import ManualServiceEvent

    return _inventory_types() + (ManualServiceEvent,)


def _replay_targets(session: Session) -> dict[str, scan_projection.ReplayScope]:
    return session.info.setdefault(_REPLAY_TARGETS, {})  # type: ignore[no-any-return]


def _pending(session: Session) -> set[str]:
    return session.info.setdefault(_PENDING, set())  # type: ignore[no-any-return]


def _inventory_pending(session: Session) -> set[str]:
    return session.info.setdefault(_INVENTORY_PENDING, set())  # type: ignore[no-any-return]


def _timeline_pending(session: Session) -> set[str]:
    return session.info.setdefault(_TIMELINE_PENDING, set())  # type: ignore[no-any-return]


def _savepoints(
    session: Session,
) -> dict[
    SessionTransaction,
    tuple[set[str], set[str], set[str], dict[str, scan_projection.ReplayScope]],
]:
    return session.info.setdefault(_SAVEPOINTS, {})  # type: ignore[no-any-return]


def _has_source_changes(session: Session) -> bool:
    return any(
        isinstance(row, _source_types())
        for rows in (session.new, session.dirty, session.deleted)
        for row in rows
    )


def _collect(session: Session, _flush_context: Any, _instances: Any) -> None:
    if session.info.get(_REBUILDING):
        return
    _collect_changes(session)


def prepare_read(session: Session) -> None:
    """Flush source writes, then finish pending read-model projections.

    Explicit flushes only collect scopes. Steady reads do no validation or
    rebuilding; manual-only writes never replay scan history.
    """
    if session.info.get(_REBUILDING):
        return
    if not (
        session.info.get(_PENDING)
        or session.info.get(_INVENTORY_PENDING)
        or session.info.get(_TIMELINE_PENDING)
        or _has_source_changes(session)
    ):
        return
    session.info[_REBUILDING] = True
    evidence_scopes: set[str] = set()
    inventory_scopes: set[str] = set()
    timeline_scopes: set[str] = set()
    replay_targets: dict[str, scan_projection.ReplayScope] = {}
    try:
        # Collect before cascading deletion and before flush forgets old scopes.
        _collect_changes(session)
        session.flush()
        evidence_scopes = session.info.pop(_PENDING, set())
        inventory_scopes = session.info.pop(_INVENTORY_PENDING, set()) | evidence_scopes
        timeline_scopes = session.info.pop(_TIMELINE_PENDING, set()) | evidence_scopes
        replay_targets = session.info.pop(_REPLAY_TARGETS, {})
        session.info.pop("timeline_raw", None)
        for engagement_id in sorted(evidence_scopes):
            scan_projection.rebuild_engagement(session, engagement_id, replay_targets.get(engagement_id))
        session.flush()
        for engagement_id in sorted(inventory_scopes):
            inventory_projection.rebuild_inventory(session, engagement_id)
        for engagement_id in sorted(timeline_scopes):
            timeline_projection.rebuild_timeline(session, engagement_id)
        session.flush()
    except BaseException:
        if session.is_active:
            # Reducer/serialization errors can leave the transaction usable;
            # retain invalidations so a retry cannot commit stale rows.
            _pending(session).update(evidence_scopes)
            _inventory_pending(session).update(inventory_scopes)
            _timeline_pending(session).update(timeline_scopes)
            for engagement_id, scope in replay_targets.items():
                _replay_targets(session).setdefault(
                    engagement_id, scan_projection.ReplayScope(),
                ).merge(scope)
        else:
            session.info.pop(_PENDING, None)
            session.info.pop(_INVENTORY_PENDING, None)
            session.info.pop(_TIMELINE_PENDING, None)
            session.info.pop(_REPLAY_TARGETS, None)
        raise
    finally:
        session.info.pop(_REBUILDING, None)
        session.info.pop("timeline_raw", None)


def _collect_changes(session: Session) -> None:
    from penrecon.models import (
        Host, HostScanDelta, HostScanEvidence, ManualServiceEvent, Observation, Scan,
        ScanEvidenceComplete,
    )

    # Source scopes survive FK cascades even when dependent rows never load.
    # This collector also runs explicitly while projection hooks are guarded.
    evidence_scopes = _pending(session)
    inventory_scopes = _inventory_pending(session)
    timeline_scopes = _timeline_pending(session)
    # Reading an expired source attribute must not flush (and delete) that
    # source before its ownership scope has been collected.
    with session.no_autoflush:
        for rows in (session.new, session.dirty, session.deleted):
            for row in rows:
                if not isinstance(row, _source_types()):
                    continue
                state = inspect(row)
                assert state is not None
                scopes = {row.engagement_id}
                history = state.attrs.engagement_id.history
                scopes.update(history.deleted)
                if history.has_changes() and state.identity and not history.deleted:
                    # An expired scope can be assigned without loading its old
                    # value. Query by stable PK before flush loses that scope.
                    mapper = state.mapper
                    previous = session.connection().execute(
                        select(mapper.local_table.c.engagement_id).where(*(
                            column == value
                            for column, value in zip(mapper.primary_key, state.identity, strict=True)
                        ))
                    ).scalar_one_or_none()
                    if previous is not None:
                        scopes.add(previous)
                if isinstance(row, ManualServiceEvent):
                    timeline_scopes.update(scopes)
                    continue
                inventory_scopes.update(scopes)
                if not isinstance(row, _evidence_types()):
                    continue
                if (
                    isinstance(row, Host)
                    and row not in session.new and row not in session.deleted
                    and not state.attrs.ip.history.has_changes()
                    and not history.has_changes()
                ):
                    # Rediscovery touches last_seen, not historical evidence.
                    continue
                evidence_scopes.update(scopes)
                for engagement_id in scopes:
                    target = _replay_targets(session).setdefault(
                        engagement_id, scan_projection.ReplayScope(),
                    )
                    if len(scopes) > 1 or (history.has_changes() and state.identity):
                        target.full = True
                    if isinstance(row, Host):
                        if row in session.deleted or (state.attrs.ip.history.has_changes() and state.identity):
                            # Renaming/deleting a legacy identity can reattribute
                            # raw evidence on another canonical sibling.
                            target.full = True
                        elif row.id is None:
                            target.new_hosts[id(row)] = row
                        else:
                            target.hosts.add(row.id)
                    elif isinstance(row, Scan):
                        target.scans[id(row)] = row
                        if row in session.deleted and row.id is not None and row.id not in target.deleted_scans:
                            # Capture dependencies before FK cascades remove
                            # evidence and persisted deltas, even on explicit flush.
                            target.deleted_scans.add(row.id)
                            complete = session.exec(select(ScanEvidenceComplete.scan_id).where(
                                ScanEvidenceComplete.engagement_id == engagement_id,
                                ScanEvidenceComplete.scan_id == row.id,
                            )).first()
                            if complete is None:
                                target.full = True
                            for model in (HostScanDelta, HostScanEvidence, Observation):
                                target.hosts.update(session.execute(
                                    select(model.host_id).where(
                                        model.engagement_id == engagement_id,
                                        model.scan_id == row.id,
                                    )
                                ).scalars())
                    elif isinstance(row, (HostScanEvidence, Observation)):
                        target.hosts.add(row.host_id)
                        host_history = state.attrs.host_id.history
                        target.hosts.update(host_history.deleted)
                        if host_history.has_changes() and state.identity and not host_history.deleted:
                            target.full = True


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
    adapter = scan_projection.timeline_adapter()
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
    """Populate missing additive read models without changing source rows.

    Only missing scan states replay evidence. Missing inventory and timeline
    metadata reuse persisted projections and manual events, including when
    a new table was added on startup.
    """
    from penrecon.models import (
        CurrentService, Host, HostScanDelta, HostScanState, HostSummary, HostSummaryTag,
        HostTimelineEntry, ManualServiceEvent, Service,
    )

    prepare_read(session)
    evidence_scopes = set(session.execute(
        select(Host.engagement_id).outerjoin(
            HostScanState,
            (col(HostScanState.host_id) == col(Host.id))
            & (col(HostScanState.engagement_id) == col(Host.engagement_id)),
        ).where(col(HostScanState.host_id).is_(None)).distinct()
    ).scalars())
    inventory_scopes = evidence_scopes | set(session.execute(
        select(Host.engagement_id).outerjoin(
            HostSummary,
            (col(HostSummary.host_id) == col(Host.id))
            & (col(HostSummary.engagement_id) == col(Host.engagement_id)),
        ).where(col(HostSummary.host_id).is_(None)).distinct()
    ).scalars()) | set(session.execute(
        select(Service.engagement_id).outerjoin(
            CurrentService,
            (col(CurrentService.service_id) == col(Service.id))
            & (col(CurrentService.engagement_id) == col(Service.engagement_id)),
        ).where(col(CurrentService.service_id).is_(None)).distinct()
    ).scalars())
    # Empty tag membership is valid. Only an actual summary tag without its
    # corresponding membership row indicates a missing additive projection.
    tags = func.json_each(HostSummary.tags).table_valued("value")
    inventory_scopes.update(session.execute(
        select(HostSummary.engagement_id).select_from(HostSummary).join(tags, true())
        .outerjoin(
            HostSummaryTag,
            (col(HostSummaryTag.engagement_id) == col(HostSummary.engagement_id))
            & (col(HostSummaryTag.host_id) == col(HostSummary.host_id))
            & (col(HostSummaryTag.tag) == tags.c.value),
        ).where(col(HostSummaryTag.host_id).is_(None)).distinct()
    ).scalars())
    timeline_scopes: set[str] = set()
    for model, source, source_id in (
        (HostScanDelta, "scan", HostScanDelta.scan_id),
        (ManualServiceEvent, "manual", ManualServiceEvent.id),
    ):
        timeline_scopes.update(session.execute(
            select(model.engagement_id).outerjoin(
                HostTimelineEntry,
                (col(HostTimelineEntry.engagement_id) == col(model.engagement_id))
                & (col(HostTimelineEntry.host_id) == col(model.host_id))
                & (col(HostTimelineEntry.source) == source)
                & (col(HostTimelineEntry.source_id) == col(source_id)),
            ).where(col(HostTimelineEntry.host_id).is_(None)).distinct()
        ).scalars())
    if not (inventory_scopes or timeline_scopes):
        return
    _pending(session).update(evidence_scopes)
    _inventory_pending(session).update(inventory_scopes)
    _timeline_pending(session).update(timeline_scopes)
    prepare_read(session)


def _before_commit(session: Session) -> None:
    prepare_read(session)


def _after_transaction_create(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        # begin_nested flushes outer source rows before creating the savepoint.
        # A read can consume their invalidations inside it; rollback must then
        # restore all invalidations because projection writes also rolled back.
        _savepoints(session)[transaction] = (
            set(_pending(session)), set(_inventory_pending(session)),
            set(_timeline_pending(session)),
            {key: value.copy() for key, value in _replay_targets(session).items()},
        )


def _clear(session: Session) -> None:
    session.info.pop(_PENDING, None)
    session.info.pop(_INVENTORY_PENDING, None)
    session.info.pop(_TIMELINE_PENDING, None)
    session.info.pop(_SAVEPOINTS, None)
    session.info.pop(_REPLAY_TARGETS, None)
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
        evidence_scopes, inventory_scopes, timeline_scopes, targets = _savepoints(session).pop(
            transaction, (set(), set(), set(), {}),
        )
        session.info[_PENDING] = evidence_scopes
        session.info[_INVENTORY_PENDING] = inventory_scopes
        session.info[_TIMELINE_PENDING] = timeline_scopes
        session.info[_REPLAY_TARGETS] = targets
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
