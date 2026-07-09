from __future__ import annotations

from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import Host, Scan, Service
from penrecon.queries import host_change


def _change(session: Session, ip: str) -> str:
    """Call host_change with the same scan baseline host_rows computes."""
    scan_ids = session.exec(select(Scan.id).order_by(Scan.imported_at.desc())).all()  # type: ignore[attr-defined]
    return host_change(
        session, _host_id(session, ip),
        scan_count=len(scan_ids), latest_scan_id=(scan_ids[0] if scan_ids else None),
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
    ingest_scan(session, _scan("10.0.0.1", 80, "1.0"), "a.xml", "nmap")
    assert _change(session, "10.0.0.1") == ""


def test_host_new_in_latest_scan_marks_new(session: Session) -> None:
    # scan A establishes a baseline; scan B introduces a host absent from A
    ingest_scan(session, _scan("10.0.0.9", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.10", 80, "1.0"), "b.xml", "nmap")
    assert _change(session, "10.0.0.10") == "new"


def test_host_only_in_older_scan_is_not_new(session: Session) -> None:
    # host seen only in the first scan, absent from the latest: stale, not new
    ingest_scan(session, _scan("10.0.0.11", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.12", 80, "1.0"), "b.xml", "nmap")
    assert _change(session, "10.0.0.11") == ""


def test_unchanged_rescan_marks_nothing(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.2", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.2", 80, "1.0"), "b.xml", "nmap")
    assert _change(session, "10.0.0.2") == ""


def test_version_change_marks_changed(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.3", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.3", 80, "2.0"), "b.xml", "nmap")
    assert _change(session, "10.0.0.3") == "changed"


def test_added_port_marks_changed_removed_ignored(session: Session) -> None:
    # latest scan sees a new port (80) and drops the old one (22): the added port
    # flags "changed"; the removal is out of scope and never flips it on its own.
    ingest_scan(session, _scan("10.0.0.4", 22, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.4", 80, "1.0"), "b.xml", "nmap")
    assert _change(session, "10.0.0.4") == "changed"


def test_manual_edit_never_flags(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.5", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.5", 80, "1.0"), "b.xml", "nmap")
    svc = session.exec(select(Service).where(Service.port == 80)).one()
    svc.m_version = "9.9-manual"
    session.commit()
    # manual overrides carry no observation; the scan story is unchanged
    assert _change(session, "10.0.0.5") == ""
