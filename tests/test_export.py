from __future__ import annotations

import csv
import io

from sqlmodel import Session

from penrecon.ingest import ingest_scan
from penrecon.models import Annotation, Host, Status
from penrecon.queries import EXPORT_COLUMNS, export_rows


def _scan(ip: str, hostname: str, service: str, port: int) -> bytes:
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{hostname}"/></hostnames>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="{service}" product="db" version="14"/>'
        f"</port></ports></host></nmaprun>"
    ).encode()


def test_one_row_per_service_and_serviceless_host(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.5", "db.corp.local", "postgresql", 5432), "a.xml", "nmap")
    session.add(Host(ip="10.0.0.9"))  # host with no services must still appear
    session.commit()
    rows = export_rows(session)
    assert [r["ip"] for r in rows] == ["10.0.0.5", "10.0.0.9"]
    svc = rows[0]
    assert svc["port"] == "5432" and svc["proto"] == "tcp" and svc["state"] == "open"
    assert svc["service"] == "postgresql" and svc["hostnames"] == "db.corp.local"
    empty = rows[1]
    assert empty["port"] == "" and empty["service"] == "" and empty["status"] == Status.new.value


def test_host_status_and_tags_included(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.5", "h", "ssh", 22), "a.xml", "nmap")
    host = session.exec(__import__("sqlmodel").select(Host).where(Host.ip == "10.0.0.5")).one()
    assert host.id is not None
    session.add(Annotation(host_id=host.id,
                           status=Status.interesting, tags=["prod", "pivot"]))
    session.commit()
    r = export_rows(session)[0]
    assert r["status"] == "interesting" and r["tags"] == "prod pivot"


def test_export_neutralizes_formula_injection(session: Session) -> None:
    # a target advertises a formula-shaped service banner
    ingest_scan(session, _scan("10.0.0.7", "h.local", "=HYPERLINK(1)", 8080), "x.xml", "nmap")
    r = export_rows(session)[0]
    assert r["service"].startswith("'=")          # neutralized, not executable
    assert r["service"] == "'=HYPERLINK(1)"


def test_rows_are_valid_csv(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.5", "db.corp.local", "postgresql", 5432), "a.xml", "nmap")
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=EXPORT_COLUMNS)
    w.writeheader()
    w.writerows(export_rows(session))
    back = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert back[0]["ip"] == "10.0.0.5" and back[0]["service"] == "postgresql"
