from __future__ import annotations

import pytest

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session

from penrecon.history import host_history
from penrecon.ingest import ingest_scan
from penrecon.queries import diff_scans, host_rows
from tests.fixtures import SCAN_A, SCAN_B


def test_diff_added_removed_changed(session: Session) -> None:
    a = ingest_scan(session, SCAN_A.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    b = ingest_scan(session, SCAN_B.encode(), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert a.id is not None and b.id is not None

    result = diff_scans(session, a.id, b.id, engagement_id=TEST_ENGAGEMENT_ID)
    by_port = {(e.port, e.kind): e for e in result.entries}

    # 443 appeared
    assert (443, "added") in by_port
    assert "nginx" in by_port[(443, "added")].after
    # 80 went open -> closed (state change is a "changed" entry, still present in both scans)
    assert (80, "changed") in by_port
    assert "open" in by_port[(80, "changed")].before
    assert "closed" in by_port[(80, "changed")].after
    # 22 version changed 8.9 -> 9.0
    assert (22, "changed") in by_port
    assert "8.9" in by_port[(22, "changed")].before
    assert "9.0" in by_port[(22, "changed")].after


@pytest.mark.parametrize(
    ("ports", "current_state"),
    [("", "open"), ('<extraports state="closed" count="1"/>', "closed")],
)
def test_snapshot_diff_does_not_inherit_replayed_port_evidence(
    session: Session, ports: str, current_state: str,
) -> None:
    baseline = (
        '<nmaprun start="100"><host><address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.0"/></port></ports>'
        "</host></nmaprun>"
    ).encode()
    omitted = (
        '<nmaprun start="200"><scaninfo protocol="tcp" services="80" numservices="1"/>'
        '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
        f"<ports>{ports}</ports></host></nmaprun>"
    ).encode()
    before = ingest_scan(session, baseline, "baseline.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    after = ingest_scan(session, omitted, "omitted.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert before.id is not None and after.id is not None
    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    _, latest = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert latest[(80, "tcp")].state == current_state

    # Snapshot comparison still reports absence, not an inferred closure or an
    # inherited open observation from a different scan.
    difference = diff_scans(session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [(entry.port, entry.proto, entry.kind) for entry in difference.entries] == [
        (80, "tcp", "removed"),
    ]
    reverse = diff_scans(session, after.id, before.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [(entry.port, entry.proto, entry.kind) for entry in reverse.entries] == [
        (80, "tcp", "added"),
    ]
