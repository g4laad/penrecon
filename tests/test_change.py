from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session, select

from penrecon.history import host_history
from penrecon.ingest import ingest_scan
from penrecon.models import Host, Service
from penrecon.queries import host_change, host_rows, resolved_services


def _change(session: Session, ip: str) -> str:
    return host_change(
        session, _host_id(session, ip), engagement_id=TEST_ENGAGEMENT_ID,
    )


def _scan(ip: str, port: int, version: str) -> bytes:
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="http" product="nginx" version="{version}" method="probed"/>'
        f"</port></ports></host></nmaprun>"
    ).encode()


def _host_id(session: Session, ip: str) -> int:
    host = session.exec(select(Host).where(Host.ip == ip)).one()
    assert host.id is not None
    return host.id


def test_first_scan_no_baseline_no_flag(session: Session) -> None:
    # a single-scan DB has no baseline: "new" would flag every host, so nothing does
    ingest_scan(session, _scan("10.0.0.1", 80, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _change(session, "10.0.0.1") == ""


def test_host_new_in_latest_scan_marks_new(session: Session) -> None:
    # scan A establishes a baseline; scan B introduces a host absent from A
    ingest_scan(session, _scan("10.0.0.9", 80, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.10", 80, "1.0"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _change(session, "10.0.0.10") == "new"


def test_host_only_in_older_scan_is_not_new(session: Session) -> None:
    # host seen only in the first scan, absent from the latest: stale, not new
    ingest_scan(session, _scan("10.0.0.11", 80, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.12", 80, "1.0"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _change(session, "10.0.0.11") == ""


def test_unchanged_rescan_marks_nothing(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.2", 80, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.2", 80, "1.0"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _change(session, "10.0.0.2") == ""


def test_version_change_marks_changed(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.3", 80, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.3", 80, "2.0"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _change(session, "10.0.0.3") == "changed"


def test_added_port_marks_changed_removed_ignored(session: Session) -> None:
    # latest scan sees a new port (80) and drops the old one (22): the added port
    # flags "changed"; the removal is out of scope and never flips it on its own.
    ingest_scan(session, _scan("10.0.0.4", 22, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.4", 80, "1.0"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert _change(session, "10.0.0.4") == "changed"


def test_manual_edit_never_flags(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.5", 80, "1.0"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.5", 80, "1.0"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    svc = session.exec(select(Service).where(Service.port == 80)).one()
    svc.m_version = "9.9-manual"
    session.commit()
    # manual overrides carry no observation; the scan story is unchanged
    assert _change(session, "10.0.0.5") == ""


def _evidence_scan(timestamp: int, ports: str, scaninfo: str = "") -> bytes:
    return (
        f'<nmaprun start="{timestamp}">{scaninfo}<host><status state="up"/>'
        '<address addr="10.0.0.20" addrtype="ipv4"/>'
        f"<ports>{ports}</ports></host></nmaprun>"
    ).encode()


def test_replay_missing_covered_and_explicit_evidence_in_scan_order(session: Session) -> None:
    baseline = _evidence_scan(
        100,
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.0"/></port>',
    )
    covered = _evidence_scan(
        300, '<extraports state="closed" count="2"/>',
        '<scaninfo protocol="tcp" services="22,80" numservices="2"/>',
    )
    partial = _evidence_scan(
        200, '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https"/></port>',
    )
    explicit = _evidence_scan(
        400, '<port protocol="tcp" portid="80"><state state="filtered"/></port>',
    )
    # Import order is not scan chronology: the partial scan predates closure.
    for filename, data in [
        ("baseline.xml", baseline), ("covered.xml", covered),
        ("partial.xml", partial), ("explicit.xml", explicit),
    ]:
        ingest_scan(session, data, filename, "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    entries, latest = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)

    assert [entry.filename for entry in entries] == [
        "baseline.xml", "partial.xml", "covered.xml", "explicit.xml",
    ]
    assert [(port.port, port.proto) for port in entries[1].not_reported] == [(80, "tcp")]
    assert [(port.port, port.proto) for port in entries[2].not_reported] == [(443, "tcp")]
    closure = entries[2].changes[0]
    assert closure.port == 80
    assert closure.before is not None and closure.after is not None
    assert (closure.before.state, closure.after.state) == ("open", "closed")
    assert (closure.after.service_name, closure.after.product, closure.after.version) == (
        "http", "nginx", "1.0",
    )
    # Aggregate coverage never creates a previously unknown port (22).
    assert set(latest) == {(80, "tcp"), (443, "tcp")}
    # Explicit evidence, unlike coverage, can clear previously observed details.
    assert latest[(80, "tcp")].state == "filtered"
    assert latest[(80, "tcp")].service_name is None
    assert latest[(80, "tcp")].product is None
    assert latest[(80, "tcp")].version is None
    services = resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert {(service.port, service.state) for service in services} == {
        (80, "filtered"), (443, "open"),
    }


def test_coverage_without_a_unique_state_keeps_last_known_port(session: Session) -> None:
    ambiguous = _evidence_scan(
        300,
        '<extraports state="closed" count="1"/>'
        '<extraports state="filtered" count="1"/>',
        '<scaninfo protocol="tcp" services="22,80" numservices="2"/>',
    )
    baseline = _evidence_scan(
        100, '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.0"/></port>',
    )
    ingest_scan(session, baseline, "baseline.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, ambiguous, "ambiguous.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    entries, _ = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    entry = next(entry for entry in entries if entry.filename == "ambiguous.xml")
    assert entry.changes == []
    assert [(port.port, port.proto) for port in entry.not_reported] == [(80, "tcp")]
    services = resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [(service.port, service.state, service.version) for service in services] == [(80, "open", "1.0")]


def test_deleting_scan_restores_previous_current_state_and_delta(session: Session) -> None:
    baseline = ingest_scan(
        session, _scan("10.0.0.30", 80, "1.0"), "baseline.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    changed = ingest_scan(
        session, _scan("10.0.0.30", 80, "2.0"), "changed.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    host_id = _host_id(session, "10.0.0.30")
    assert _change(session, "10.0.0.30") == "changed"

    session.delete(changed)
    session.commit()
    entries, latest = host_history(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.scan_id for entry in entries] == [baseline.id]
    assert latest[(80, "tcp")].version == "1.0"
    assert resolved_services(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)[0].version == "1.0"
    assert _change(session, "10.0.0.30") == ""


def test_rolled_back_scan_deletion_restores_current_state_and_delta(session: Session) -> None:
    ingest_scan(
        session, _scan("10.0.0.31", 80, "1.0"), "baseline.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    changed = ingest_scan(
        session, _scan("10.0.0.31", 80, "2.0"), "changed.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    host_id = _host_id(session, "10.0.0.31")
    with session.begin_nested() as transaction:
        session.delete(changed)
        assert resolved_services(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)[0].version == "1.0"
        transaction.rollback()

    entries, latest = host_history(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.filename for entry in entries] == ["baseline.xml", "changed.xml"]
    assert latest[(80, "tcp")].version == "2.0"
    assert _change(session, "10.0.0.31") == "changed"
