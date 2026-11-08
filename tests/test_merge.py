from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import event
from sqlmodel import Session, select

from penrecon.ingest import ScanParseError, ingest_scan
from penrecon.models import Host, Service
from penrecon.queries.diff import diff_scans
from penrecon.queries.inventory import (
    host_rows,
    host_timeline,
    latest_observations,
    resolved_services,
)
from tests.fixtures import SCAN_A, SCAN_B, TEST_ENGAGEMENT_ID


def test_latest_observation_wins(session: Session) -> None:
    ingest_scan(
        session, SCAN_A.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )
    ingest_scan(
        session, SCAN_B.encode(), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )

    host = session.exec(select(Host).where(Host.ip == "10.0.0.1")).one()
    assert host.id is not None

    # one stable service per (port, proto): 22, 80, 443 (not duplicated across scans)
    services = session.exec(select(Service).where(Service.host_id == host.id)).all()
    assert sorted(s.port for s in services) == [22, 80, 443]

    latest = latest_observations(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert latest[(22, "tcp")].version == "9.0"  # scan B wins
    assert latest[(80, "tcp")].state == "closed"  # scan B wins

    views = {
        v.port: v
        for v in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    }
    assert views[22].version == "9.0"
    assert views[443].service_name == "https"


@pytest.mark.parametrize(
    "tool,data,match",
    [
        ("unknown", b"", "unknown tool"),
        ("nmap", SCAN_A.replace('state="open"', 'state="mystery"').encode(), "mystery"),
        ("amass", b"\xff", "Correct the file"),
    ],
)
def test_parse_errors_leave_inventory_unchanged(
    session: Session,
    tool: str,
    data: bytes,
    match: str,
) -> None:
    with pytest.raises(ScanParseError, match=match):
        ingest_scan(session, data, "bad.xml", tool, engagement_id=TEST_ENGAGEMENT_ID)
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID) == []


@pytest.mark.parametrize(
    "state",
    [
        "open",
        "closed",
        "filtered",
        "unfiltered",
        "open|filtered",
        "closed|filtered",
    ],
)
def test_imported_states_match_current_inventory_and_history(
    session: Session,
    state: str,
) -> None:
    baseline = ingest_scan(
        session,
        b"<nmaprun/>",
        "empty.xml",
        "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    scan = ingest_scan(
        session,
        SCAN_A.replace('state="open"', f'state="{state}"').encode(),
        "states.xml",
        "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    row = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    current = resolved_services(session, row.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert {view.state for view in current} == {state}
    timeline = host_timeline(session, row.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert timeline.entries[0].scan_id == scan.id
    assert {change.after.state for change in timeline.entries[0].changes} == {state}
    assert baseline.id is not None and scan.id is not None
    difference = diff_scans(
        session, baseline.id, scan.id, engagement_id=TEST_ENGAGEMENT_ID
    )
    assert [entry.after for entry in difference.entries] == [
        f"{state} ssh OpenSSH 8.9",
        f"{state} http Apache httpd 2.4.1",
    ]


def test_duplicate_scan_hosts_produce_one_inventory_identity(session: Session) -> None:
    data = (
        SCAN_A.replace("</nmaprun>", "") + SCAN_B.split('<nmaprun scanner="nmap">')[1]
    )
    scan = ingest_scan(
        session,
        data.encode(),
        "duplicates.xml",
        "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    rows = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
    assert scan.host_count == 1
    assert len(rows) == 1
    current = resolved_services(session, rows[0].id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [(view.port, view.state) for view in current] == [
        (22, "open"),
        (80, "closed"),
        (443, "open"),
    ]
    timeline = host_timeline(session, rows[0].id, engagement_id=TEST_ENGAGEMENT_ID)
    assert len(timeline.entries) == 1
    assert len(timeline.entries[0].changes) == 3


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_failed_commit_rolls_back_inventory_and_cleans_retained_raw(
    session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cleanup_fails: bool,
) -> None:
    from penrecon import ingest

    monkeypatch.setattr(ingest, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ingest, "engagement_scans_dir", lambda _: tmp_path / "scans")
    failure = RuntimeError("database commit failed")

    def fail_commit(_: Session) -> None:
        raise failure

    def fail_cleanup(*args: object, **kwargs: object) -> None:
        raise OSError("raw cleanup failed")

    if cleanup_fails:
        monkeypatch.setattr(Path, "unlink", fail_cleanup)
    event.listen(session, "before_commit", fail_commit)
    try:
        with pytest.raises(RuntimeError, match="database commit failed") as raised:
            ingest_scan(
                session,
                SCAN_A.encode(),
                "a.xml",
                "nmap",
                engagement_id=TEST_ENGAGEMENT_ID,
            )
        assert raised.value is failure
    finally:
        event.remove(session, "before_commit", fail_commit)
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID) == []
    assert bool(list(tmp_path.rglob("*.xml"))) is cleanup_fails
    if cleanup_fails:
        assert any("raw cleanup failed" in note for note in failure.__notes__)
        orphan = next(tmp_path.rglob("*.xml"))
        retry = ingest_scan(
            session, SCAN_B.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
        )
        assert retry.raw_path is not None
        retained = tmp_path / retry.raw_path
        assert retained != orphan
        assert orphan.read_bytes() == SCAN_A.encode()
        assert retained.read_bytes() == SCAN_B.encode()
    else:
        scan = ingest_scan(
            session,
            SCAN_A.encode(),
            "retry.xml",
            "nmap",
            engagement_id=TEST_ENGAGEMENT_ID,
        )
        assert scan.host_count == 1


def test_refresh_failure_does_not_remove_committed_raw(
    session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from penrecon import ingest

    monkeypatch.setattr(ingest, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ingest, "engagement_scans_dir", lambda _: tmp_path / "scans")

    def fail_refresh(*args: object, **kwargs: object) -> None:
        raise RuntimeError("refresh failed")

    monkeypatch.setattr(session, "refresh", fail_refresh)
    with pytest.raises(RuntimeError, match="refresh failed"):
        ingest_scan(
            session, SCAN_A.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
        )
    assert len(host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)) == 1
    assert [path.read_bytes() for path in tmp_path.rglob("*.xml")] == [SCAN_A.encode()]


def test_partial_raw_write_failure_rolls_back_and_removes_file(
    session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from penrecon import ingest

    monkeypatch.setattr(ingest, "DATA_DIR", tmp_path)
    monkeypatch.setattr(ingest, "engagement_scans_dir", lambda _: tmp_path / "scans")
    write_bytes = Path.write_bytes

    def fail_write(path: Path, data: bytes) -> int:
        write_bytes(path, data[:10])
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_bytes", fail_write)
    with pytest.raises(OSError, match="disk full"):
        ingest_scan(
            session, SCAN_A.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
        )
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID) == []
    assert list(tmp_path.rglob("*.xml")) == []
