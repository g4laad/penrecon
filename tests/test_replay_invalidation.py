from __future__ import annotations

from sqlmodel import Session, select

from penrecon.history import host_history
from penrecon.ingest import ingest_scan
from penrecon.models import Host
from penrecon.queries.inventory import host_change, host_rows, resolved_services
from tests.fixtures import TEST_ENGAGEMENT_ID


def _scan(ip: str, version: str = "1") -> bytes:
    return (
        f'<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        f'<service name="http" version="{version}"/></port></ports></host></nmaprun>'
    ).encode()


def _host(session: Session, ip: str) -> Host:
    return session.exec(select(Host).where(
        Host.engagement_id == TEST_ENGAGEMENT_ID, Host.ip == ip,
    )).one()


def test_deleting_unrelated_latest_scan_restores_previous_new_marker(session: Session) -> None:
    for ip in ("10.0.0.1", "10.0.0.2"):
        ingest_scan(session, _scan(ip), f"{ip}.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    latest = ingest_scan(
        session, _scan("10.0.0.3"), "latest.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    host = _host(session, "10.0.0.2")
    assert host.id is not None
    assert host_change(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == ""
    session.delete(latest)
    session.flush()  # FK cascades must not erase the pending replay's dependencies.
    session.commit()

    assert host_change(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == "new"
    rows = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
    assert {row.ip: row.change for row in rows} == {
        "10.0.0.1": "", "10.0.0.2": "new", "10.0.0.3": "",
    }
    assert [service.version for service in resolved_services(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID,
    )] == ["1"]


def test_scan_metadata_edit_refreshes_history_after_explicit_flush(session: Session) -> None:
    scan = ingest_scan(
        session, _scan("10.0.0.1"), "original.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    ingest_scan(session, _scan("10.0.0.2"), "other.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = _host(session, "10.0.0.1")
    assert host.id is not None
    scan.filename = "renamed.xml"
    session.flush()
    session.commit()
    entries, latest = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.filename for entry in entries] == ["renamed.xml"]
    assert latest[(80, "tcp")].version == "1"


def test_nested_rollback_retains_flushed_outer_evidence_invalidation(session: Session) -> None:
    first = ingest_scan(
        session, _scan("10.0.0.1"), "baseline.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    changed = ingest_scan(
        session, _scan("10.0.0.1", "2"), "changed.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    host = _host(session, "10.0.0.1")
    assert host.id is not None
    changed.filename = "outer.xml"
    with session.begin_nested() as savepoint:
        entries, _ = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
        assert [entry.filename for entry in entries] == [first.filename, "outer.xml"]
        session.delete(changed)
        assert resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[0].version == "1"
        savepoint.rollback()
    session.commit()
    entries, _ = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.filename for entry in entries] == [first.filename, "outer.xml"]
    assert resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[0].version == "2"
