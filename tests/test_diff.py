from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session

from penrecon.ingest import ingest_scan
from penrecon.queries import diff_scans
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
