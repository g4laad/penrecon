"""Transactional scan and inventory projections, maintained only on writes.

The history reducer owns scan merge semantics; service_state owns effective
manual overrides. Evidence invalidates both projections, while inventory-only
writes reuse persisted scan state without recovering raw scans.
"""

from __future__ import annotations

from collections import defaultdict
from functools import cache
from typing import TYPE_CHECKING, Any

from pydantic import TypeAdapter
from sqlalchemy import delete, event, func, inspect, insert, true
from sqlalchemy.orm import SessionTransaction
from sqlmodel import Session, col, select


if TYPE_CHECKING:
    from penrecon.history import TimelineEntry
    from penrecon.models import Host, HostScanEvidence, Observation, Scan

_PENDING = "scan_projection_pending"
_INVENTORY_PENDING = "inventory_projection_pending"
_REBUILDING = "scan_projection_rebuilding"
_SAVEPOINTS = "scan_projection_savepoints"


@cache
def _evidence_types() -> tuple[type[Scan], type[Host], type[HostScanEvidence], type[Observation]]:
    from penrecon.models import Host, HostScanEvidence, Observation, Scan

    return Scan, Host, HostScanEvidence, Observation


@cache
def _inventory_types() -> tuple[type[Any], ...]:
    from penrecon.models import Annotation, Hostname, HostHostname, Service

    return _evidence_types() + (Annotation, Hostname, HostHostname, Service)


@cache
def _timeline_adapter() -> TypeAdapter[TimelineEntry]:
    from penrecon.history import TimelineEntry

    return TypeAdapter(TimelineEntry)


def _pending(session: Session) -> set[str]:
    return session.info.setdefault(_PENDING, set())  # type: ignore[no-any-return]


def _inventory_pending(session: Session) -> set[str]:
    return session.info.setdefault(_INVENTORY_PENDING, set())  # type: ignore[no-any-return]


def _savepoints(session: Session) -> dict[SessionTransaction, tuple[set[str], set[str]]]:
    return session.info.setdefault(_SAVEPOINTS, {})  # type: ignore[no-any-return]


def _has_source_changes(session: Session) -> bool:
    return any(
        isinstance(row, _inventory_types())
        for rows in (session.new, session.dirty, session.deleted)
        for row in rows
    )


def _collect(session: Session, _flush_context: Any, _instances: Any) -> None:
    if session.info.get(_REBUILDING):
        return
    _collect_changes(session)


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


def _rebuild_inventory(session: Session, engagement_id: str) -> None:
    from penrecon.models import (
        Annotation, CurrentService, Host, Hostname, HostHostname, HostScanState,
        HostSummary, HostSummaryTag, Observation, Service, Status,
    )
    from penrecon.queries import service_state

    states = {
        row.host_id: row for row in session.execute(
            select(HostScanState).where(HostScanState.engagement_id == engagement_id)
        ).scalars()
    }
    annotations = {
        row.host_id: row for row in session.execute(
            select(Annotation).where(
                Annotation.engagement_id == engagement_id,
                col(Annotation.host_id).is_not(None),
            )
        ).scalars()
    }
    names: dict[int, list[str]] = defaultdict(list)
    for host_id, name in session.execute(
        select(HostHostname.host_id, Hostname.name).join(
            Hostname,
            (col(Hostname.id) == col(HostHostname.hostname_id))
            & (col(Hostname.engagement_id) == col(HostHostname.engagement_id)),
        ).where(
            HostHostname.engagement_id == engagement_id,
            HostHostname.hidden == False,  # noqa: E712
        ).order_by(Hostname.name)
    ):
        names[host_id].append(name)
    services: dict[int, list[Service]] = defaultdict(list)
    for service in session.execute(
        select(Service).where(Service.engagement_id == engagement_id)
        .order_by(col(Service.port), Service.proto, col(Service.id))
    ).scalars():
        services[service.host_id].append(service)

    current_rows: list[dict[str, Any]] = []
    summary_rows: list[dict[str, Any]] = []
    tag_rows: list[dict[str, Any]] = []
    for host in session.execute(
        select(Host).where(Host.engagement_id == engagement_id)
    ).scalars():
        assert host.id is not None
        state = states.get(host.id)
        latest: dict[tuple[int, str], Observation] = {}
        for record in state.latest if state else []:
            scanned = Observation.model_validate(record)
            latest[(scanned.port, scanned.proto)] = scanned
        open_services: list[tuple[int, str | None]] = []
        for service in services.get(host.id, []):
            observation = latest.get((service.port, service.proto))
            effective = service_state(service, observation)
            current_rows.append({
                "engagement_id": engagement_id,
                "service_id": service.id,
                "host_id": host.id,
                "port": service.port,
                "proto": service.proto,
                "state": effective.state,
                "service_name": effective.service_name,
                "product": effective.product,
                "version": effective.version,
                "observation_id": observation.id if observation else None,
                "last_seen": observation.observed_at.strftime("%Y-%m-%d %H:%M") if observation else "",
                "manual": observation is None or any((
                    service.m_state, service.m_service_name, service.m_product, service.m_version,
                )),
                "service_name_lower": (effective.service_name or "").lower(),
                "search_text": " ".join(value for value in (
                    effective.service_name, effective.product, effective.version,
                ) if value).lower(),
            })
            if effective.state == "open":
                open_services.append((service.port, effective.service_name))
        # TCP and UDP may share a port, with only one having a name.
        open_services.sort(key=lambda value: (value[0], value[1] or ""))
        annotation = annotations.get(host.id)
        tags = annotation.tags if annotation else []
        hostnames = names.get(host.id, [])
        change = state.change if state else ""
        ip_sort = "4294967296"
        parts = host.ip.split(".")
        if len(parts) == 4 and all(part.isascii() and part.isdecimal() for part in parts):
            octets = [int(part) for part in parts]
            if all(value <= 255 for value in octets):
                # Legacy dotted addresses can retain leading zeroes.
                numeric_ip = sum(value << shift for value, shift in zip(octets, (24, 16, 8, 0), strict=True))
                ip_sort = f"{numeric_ip:010d}"
        summary_rows.append({
            "engagement_id": engagement_id,
            "host_id": host.id,
            "ip": host.ip,
            "ip_sort": ip_sort,
            "open_count": len(open_services),
            "status": str(annotation.status if annotation else Status.new),
            "triaged": annotation is not None,
            "change": change,
            "change_rank": {"new": 0, "changed": 1}.get(change, 2),
            "hostnames": hostnames,
            "tags": tags,
            "open_services": open_services,
            "search_values": [value.lower() for value in (
                host.ip, *hostnames, *(name for _port, name in open_services if name), *tags,
            )],
        })
        tag_rows.extend({
            "engagement_id": engagement_id, "host_id": host.id, "tag": tag,
        } for tag in sorted(set(tags)))

    for model, rows in (
        (CurrentService, current_rows), (HostSummary, summary_rows), (HostSummaryTag, tag_rows),
    ):
        session.execute(delete(model).where(col(model.engagement_id) == engagement_id))
        for start in range(0, len(rows), 500):
            session.execute(insert(model), rows[start:start + 500])


def prepare_read(session: Session) -> None:
    """Flush source writes, then finish pending scan and inventory projections.

    Explicit flushes only collect scopes. Steady reads do no validation or
    rebuilding; manual-only writes never replay scan history.
    """
    if session.info.get(_REBUILDING):
        return
    if not (
        session.info.get(_PENDING)
        or session.info.get(_INVENTORY_PENDING)
        or _has_source_changes(session)
    ):
        return
    session.info[_REBUILDING] = True
    evidence_scopes: set[str] = set()
    inventory_scopes: set[str] = set()
    try:
        # Collect before cascading deletion and before flush forgets old scopes.
        _collect_changes(session)
        session.flush()
        evidence_scopes = session.info.pop(_PENDING, set())
        inventory_scopes = session.info.pop(_INVENTORY_PENDING, set()) | evidence_scopes
        session.info.pop("timeline_raw", None)
        for engagement_id in sorted(evidence_scopes):
            _rebuild_engagement(session, engagement_id)
        session.flush()
        for engagement_id in sorted(inventory_scopes):
            _rebuild_inventory(session, engagement_id)
        session.flush()
    except BaseException:
        if session.is_active:
            # Reducer/serialization errors can leave the transaction usable;
            # retain both invalidations so a retry cannot commit stale rows.
            _pending(session).update(evidence_scopes)
            _inventory_pending(session).update(inventory_scopes)
        else:
            session.info.pop(_PENDING, None)
            session.info.pop(_INVENTORY_PENDING, None)
        raise
    finally:
        session.info.pop(_REBUILDING, None)
        session.info.pop("timeline_raw", None)


def _collect_changes(session: Session) -> None:
    # Source scopes survive FK cascades even when dependent rows never load.
    # This collector also runs explicitly while projection hooks are guarded.
    evidence_scopes = _pending(session)
    inventory_scopes = _inventory_pending(session)
    # Reading an expired source attribute must not flush (and delete) that
    # source before its ownership scope has been collected.
    with session.no_autoflush:
        for rows in (session.new, session.dirty, session.deleted):
            for row in rows:
                if not isinstance(row, _inventory_types()):
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
                inventory_scopes.update(scopes)
                if isinstance(row, _evidence_types()):
                    evidence_scopes.update(scopes)


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
    """Populate missing additive read models without changing source rows.

    Only missing scan states replay evidence. Missing inventory rows reuse
    complete scan projections, including when a new table was added on startup.
    """
    from penrecon.models import (
        CurrentService, Host, HostScanState, HostSummary, HostSummaryTag, Service,
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
    if not inventory_scopes:
        return
    _pending(session).update(evidence_scopes)
    _inventory_pending(session).update(inventory_scopes)
    prepare_read(session)


def _before_commit(session: Session) -> None:
    prepare_read(session)


def _after_transaction_create(session: Session, transaction: SessionTransaction) -> None:
    if transaction.nested:
        # begin_nested flushes outer source rows before creating the savepoint.
        # A read can consume their invalidations inside it; rollback must then
        # restore both because the projection writes have also rolled back.
        _savepoints(session)[transaction] = (
            set(_pending(session)), set(_inventory_pending(session)),
        )


def _clear(session: Session) -> None:
    session.info.pop(_PENDING, None)
    session.info.pop(_INVENTORY_PENDING, None)
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
        evidence_scopes, inventory_scopes = _savepoints(session).pop(transaction, (set(), set()))
        session.info[_PENDING] = evidence_scopes
        session.info[_INVENTORY_PENDING] = inventory_scopes
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
