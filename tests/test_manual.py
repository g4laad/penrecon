from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import Host, HostHostname, ObsState, Service
from penrecon.queries import _hostnames_for, latest_observations, resolved_services


def _scan(ip: str, port: int, version: str, hostname: str) -> bytes:
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{hostname}" type="user"/></hostnames>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="http" product="nginx" version="{version}" method="probed"/>'
        f"</port></ports></host></nmaprun>"
    ).encode()


def test_manual_override_wins_over_rescan(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.1", 443, "1.25", "a.example"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    svc = session.exec(select(Service).where(Service.port == 443)).one()
    svc.m_version = "9.9-manual"
    session.commit()

    # a newer scan reports a different version
    ingest_scan(session, _scan("10.0.0.1", 443, "2.0", "a.example"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)

    host = session.exec(select(Host).where(Host.ip == "10.0.0.1")).one()
    assert host.id is not None
    view = {s.port: s for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert view[443].version == "9.9-manual"  # manual wins, not scan's 2.0


def test_deleted_service_reappears_fresh_on_rescan(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.2", 22, "1.0", "b.example"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = session.exec(select(Host).where(Host.ip == "10.0.0.2")).one()
    assert host.id is not None
    svc = session.exec(select(Service).where(Service.port == 22)).one()

    # Delete only current identity/overrides; immutable scan evidence survives.
    svc.m_version = "discard-on-delete"
    session.commit()
    session.delete(svc)
    session.commit()
    assert 22 not in {s.port for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}  # truly gone
    assert latest_observations(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[(22, "tcp")].version == "1.0"

    # a later scan re-creates it fresh (new row, new observation)
    ingest_scan(session, _scan("10.0.0.2", 22, "2.0", "b.example"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    view = {s.port: s for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert 22 in view
    assert view[22].version == "2.0"  # fresh from the new scan, nothing stale


def test_hidden_hostname_stays_hidden_across_rescan(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.3", 80, "1.0", "keep.example"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = session.exec(select(Host).where(Host.ip == "10.0.0.3")).one()
    assert host.id is not None
    link = session.exec(
        select(HostHostname).where(HostHostname.host_id == host.id)
    ).one()
    link.hidden = True
    session.commit()

    ingest_scan(session, _scan("10.0.0.3", 80, "1.0", "keep.example"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _hostnames_for(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == []  # sticky delete, not resurrected


def test_manual_only_service_shows(session: Session) -> None:
    # a service added by hand with no scan observation still appears
    host = Host(ip="10.0.0.4", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(host)
    session.commit()
    session.refresh(host)
    assert host.id is not None
    session.add(Service(host_id=host.id, port=8080, proto="tcp", m_state=ObsState.open,
                        m_service_name="http-proxy", engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()

    view = {s.port: s for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert view[8080].state == "open"
    assert view[8080].service_name == "http-proxy"
    assert view[8080].manual is True
