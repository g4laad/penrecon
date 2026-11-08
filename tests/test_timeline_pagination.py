from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import delete
from sqlmodel import Session

from penrecon import projections
from penrecon.history import timeline
from penrecon.models import Engagement, Host, HostScanEvidence, HostTimelineEntry, ManualServiceEvent, Scan
from tests.fixtures import TEST_ENGAGEMENT_ID


_START = datetime(2026, 1, 1, tzinfo=UTC)


def _host(session: Session, *, engagement_id: str = TEST_ENGAGEMENT_ID) -> int:
    host = Host(engagement_id=engagement_id, ip="10.0.0.1")
    session.add(host)
    session.flush()
    assert host.id is not None
    return host.id


def _scan(
    session: Session, host_id: int, scan_id: int, occurred_at: datetime,
    *, imported_at: datetime | None = None, version: str | None = None,
    engagement_id: str = TEST_ENGAGEMENT_ID,
) -> None:
    occurred_at = occurred_at.astimezone(UTC)
    imported_at = imported_at.astimezone(UTC) if imported_at is not None else None
    session.add(Scan(
        id=scan_id, engagement_id=engagement_id, filename=f"{scan_id}.xml",
        tool="nmap", source_format="xml", imported_at=imported_at or occurred_at,
    ))
    session.flush()
    session.add(HostScanEvidence(
        engagement_id=engagement_id, host_id=host_id, scan_id=scan_id,
        scanned_at=occurred_at,
        ports=[] if version is None else [{
            "port": 80, "proto": "tcp", "state": "open", "version": version,
        }],
    ))


def _manual(
    session: Session, host_id: int, event_id: int, occurred_at: datetime,
    *, engagement_id: str = TEST_ENGAGEMENT_ID,
) -> None:
    session.add(ManualServiceEvent(
        id=event_id, engagement_id=engagement_id, host_id=host_id,
        port=443, proto="tcp", occurred_at=occurred_at, kind="changed",
        before={"state": "open", "version": "original"},
        after={"state": "closed", "version": "snapshot"},
        before_overrides={"state": None}, after_overrides={"state": "closed"},
    ))


def test_timeline_paginates_mixed_scan_and_manual_changes(session: Session) -> None:
    host_id = _host(session)
    for scan_id in range(1, 23):
        _scan(session, host_id, scan_id, _START + timedelta(seconds=scan_id * 2), version=str(scan_id))
    for event_id, second in [(1, 5), (2, 25), (3, 45)]:
        _manual(session, host_id, event_id, _START + timedelta(seconds=second))

    first = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    last = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID, page=2)

    assert (first.total, first.page, first.pages) == (25, 1, 2)
    assert [entry.id for entry in first.entries] == [
        "manual:3", "scan:22", "scan:21", "scan:20", "scan:19", "scan:18",
        "scan:17", "scan:16", "scan:15", "scan:14", "scan:13", "manual:2",
        "scan:12", "scan:11", "scan:10", "scan:9", "scan:8", "scan:7",
        "scan:6", "scan:5",
    ]
    assert [entry.id for entry in last.entries] == ["scan:4", "scan:3", "manual:1", "scan:2", "scan:1"]
    assert last.latest_change is not None and last.latest_change.id == "manual:3"
    change = last.entries[2].changes[0]
    assert change.before is not None and change.before.version == "original"
    assert change.after is not None and change.after.version == "snapshot"
    assert change.after_overrides is not None and change.after_overrides.state == "closed"


@pytest.mark.parametrize("page, expected_page", [(-100, 1), (10**100, 2)])
def test_timeline_clamps_pages_after_unchanged_filtering(
    session: Session, page: int, expected_page: int,
) -> None:
    host_id = _host(session)
    for scan_id in range(1, 24):
        _scan(session, host_id, scan_id, _START + timedelta(seconds=scan_id))
    _manual(session, host_id, 1, _START + timedelta(seconds=30))

    filtered = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID, page=page)
    unfiltered = timeline(
        session, host_id, engagement_id=TEST_ENGAGEMENT_ID,
        page=page, show_unchanged=True,
    )

    assert (filtered.total, filtered.page, filtered.pages) == (2, 1, 1)
    assert [entry.id for entry in filtered.entries] == ["manual:1", "scan:1"]
    assert filtered.entries[1].first_seen and not filtered.entries[1].changes
    assert (unfiltered.total, unfiltered.page, unfiltered.pages) == (24, expected_page, 2)
    assert unfiltered.latest_change is not None and unfiltered.latest_change.id == "manual:1"
    if expected_page == 2:
        assert [entry.id for entry in unfiltered.entries] == ["scan:4", "scan:3", "scan:2", "scan:1"]


def test_timeline_orders_utc_microseconds_import_source_and_numeric_ids(session: Session) -> None:
    host_id = _host(session)
    instant = _START.replace(microsecond=999998)
    for scan_id in [9, 10, 100]:
        _scan(session, host_id, scan_id, instant, imported_at=instant, version=str(scan_id))
    for event_id in [9, 10]:
        _manual(session, host_id, event_id, instant)
    _scan(session, host_id, 1, instant, imported_at=instant + timedelta(microseconds=1), version="1")
    _scan(
        session, host_id, 2,
        (instant + timedelta(microseconds=1)).astimezone(timezone(timedelta(hours=2))),
        imported_at=instant, version="2",
    )
    _manual(session, host_id, 1, _START + timedelta(seconds=1))
    _scan(session, host_id, 3, _START, version="3")
    _manual(session, host_id, 3, _START)

    result = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID, show_unchanged=True)

    assert [entry.id for entry in result.entries] == [
        "manual:1", "scan:2", "scan:1", "scan:100", "scan:10", "scan:9", "manual:10", "manual:9",
        "scan:3", "manual:3",
    ]
    assert result.entries[1].occurred_at == "2026-01-01T00:00:00.999999+00:00"


def test_timeline_keeps_host_and_engagement_scope_and_empty_page(session: Session) -> None:
    host_id = _host(session)
    session.add(Engagement(id="other", name="Other"))
    session.flush()
    other_host_id = _host(session, engagement_id="other")
    _scan(session, other_host_id, 1, _START, version="private", engagement_id="other")
    _manual(session, other_host_id, 1, _START, engagement_id="other")

    for queried_host, engagement_id in [(host_id, TEST_ENGAGEMENT_ID), (other_host_id, TEST_ENGAGEMENT_ID)]:
        result = timeline(session, queried_host, engagement_id=engagement_id, page=10**100)
        assert (result.entries, result.total, result.page, result.pages, result.latest_change) == ([], 0, 1, 1, None)


@pytest.mark.parametrize("flushed", [False, True], ids=["pending", "flushed"])
def test_manual_only_timeline_tracks_edits_deletes_and_rollback(
    session: Session, flushed: bool,
) -> None:
    host_id = _host(session)
    _manual(session, host_id, 1, _START)
    session.commit()
    _manual(session, host_id, 2, _START + timedelta(seconds=1))
    if flushed:
        session.flush()
    result = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.id for entry in result.entries] == ["manual:2", "manual:1"]
    session.rollback()
    assert [entry.id for entry in timeline(
        session, host_id, engagement_id=TEST_ENGAGEMENT_ID,
    ).entries] == ["manual:1"]

    _manual(session, host_id, 2, _START + timedelta(seconds=1))
    session.commit()
    event = session.get(ManualServiceEvent, 1)
    assert event is not None
    event.occurred_at = _START + timedelta(seconds=2)
    if flushed:
        session.flush()
    result = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.id for entry in result.entries] == ["manual:1", "manual:2"]
    assert result.latest_change is not None and result.latest_change.id == "manual:1"
    session.delete(event)
    if flushed:
        session.flush()
    result = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.id for entry in result.entries] == ["manual:2"]
    assert result.total == 1
    session.rollback()
    assert [entry.id for entry in timeline(
        session, host_id, engagement_id=TEST_ENGAGEMENT_ID,
    ).entries] == ["manual:2", "manual:1"]


@pytest.mark.parametrize("inner_write", [False, True])
def test_timeline_savepoint_rollback_keeps_outer_manual_action(
    session: Session, inner_write: bool,
) -> None:
    host_id = _host(session)
    _manual(session, host_id, 1, _START)
    session.commit()
    _manual(session, host_id, 2, _START + timedelta(seconds=1))
    with session.begin_nested() as savepoint:
        assert [entry.id for entry in timeline(
            session, host_id, engagement_id=TEST_ENGAGEMENT_ID,
        ).entries] == ["manual:2", "manual:1"]
        if inner_write:
            _manual(session, host_id, 3, _START + timedelta(seconds=2))
            assert [entry.id for entry in timeline(
                session, host_id, engagement_id=TEST_ENGAGEMENT_ID,
            ).entries] == ["manual:3", "manual:2", "manual:1"]
        savepoint.rollback()
    result = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.id for entry in result.entries] == ["manual:2", "manual:1"]
    session.commit()
    assert timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID) == result


def test_deleting_first_scan_refreshes_timeline_visibility(session: Session) -> None:
    host_id = _host(session)
    _scan(session, host_id, 1, _START)
    _scan(session, host_id, 2, _START + timedelta(seconds=1))
    session.commit()
    assert [entry.id for entry in timeline(
        session, host_id, engagement_id=TEST_ENGAGEMENT_ID,
    ).entries] == ["scan:1"]
    scan = session.get(Scan, 1)
    assert scan is not None
    session.delete(scan)
    session.flush()
    result = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.id for entry in result.entries] == ["scan:2"]
    assert result.entries[0].first_seen and not result.entries[0].changes
    assert result.latest_change == result.entries[0]
    session.commit()
    assert timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID) == result


def test_backfill_restores_manual_only_timeline_without_changing_snapshots(session: Session) -> None:
    host_id = _host(session)
    _manual(session, host_id, 1, _START)
    _manual(session, host_id, 2, _START + timedelta(seconds=1))
    session.commit()
    expected = timeline(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    engine = session.get_bind()
    session.commit()
    with engine.begin() as connection:
        connection.execute(delete(HostTimelineEntry))
    with Session(engine) as restored:
        projections.backfill_missing(restored)
        restored.commit()
        assert timeline(restored, host_id, engagement_id=TEST_ENGAGEMENT_ID) == expected
        projections.backfill_missing(restored)
        restored.commit()
        assert timeline(restored, host_id, engagement_id=TEST_ENGAGEMENT_ID) == expected
