from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import Host, Service
from penrecon.queries import resolved_services, latest_observations
from tests.fixtures import SCAN_A, SCAN_B


def test_latest_observation_wins(session: Session) -> None:
    ingest_scan(session, SCAN_A.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, SCAN_B.encode(), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)

    host = session.exec(select(Host).where(Host.ip == "10.0.0.1")).one()
    assert host.id is not None

    # one stable service per (port, proto): 22, 80, 443 (not duplicated across scans)
    services = session.exec(select(Service).where(Service.host_id == host.id)).all()
    assert sorted(s.port for s in services) == [22, 80, 443]

    latest = latest_observations(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert latest[(22, "tcp")].version == "9.0"   # scan B wins
    assert latest[(80, "tcp")].state == "closed"  # scan B wins

    views = {v.port: v for v in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert views[22].version == "9.0"
    assert views[443].service_name == "https"
