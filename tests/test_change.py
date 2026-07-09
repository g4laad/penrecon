from __future__ import annotations

from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import Host, Service
from penrecon.queries import host_change


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


def test_first_scan_marks_new(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.1", 80, "1.0"), "a.xml", "nmap")
    assert host_change(session, _host_id(session, "10.0.0.1")) == "new"


def test_unchanged_rescan_marks_nothing(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.2", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.2", 80, "1.0"), "b.xml", "nmap")
    assert host_change(session, _host_id(session, "10.0.0.2")) == ""


def test_version_change_marks_changed(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.3", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.3", 80, "2.0"), "b.xml", "nmap")
    assert host_change(session, _host_id(session, "10.0.0.3")) == "changed"


def test_added_port_marks_changed_removed_ignored(session: Session) -> None:
    # latest scan sees a new port (80) and drops the old one (22): the added port
    # flags "changed"; the removal is out of scope and never flips it on its own.
    ingest_scan(session, _scan("10.0.0.4", 22, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.4", 80, "1.0"), "b.xml", "nmap")
    assert host_change(session, _host_id(session, "10.0.0.4")) == "changed"


def test_manual_edit_never_flags(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.5", 80, "1.0"), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.5", 80, "1.0"), "b.xml", "nmap")
    svc = session.exec(select(Service).where(Service.port == 80)).one()
    svc.m_version = "9.9-manual"
    session.commit()
    # manual overrides carry no observation; the scan story is unchanged
    assert host_change(session, _host_id(session, "10.0.0.5")) == ""
