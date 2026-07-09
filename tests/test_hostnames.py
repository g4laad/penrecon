from __future__ import annotations

from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import Host, HostHostname
from penrecon.queries import _hostnames_for


def _scan(ip: str, hostnames: list[str]) -> bytes:
    hn = "".join(f'<hostname name="{h}" type="user"/>' for h in hostnames)
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><hostnames>{hn}</hostnames>'
        f'<ports><port protocol="tcp" portid="22"><state state="open"/>'
        f'<service name="ssh" method="probed"/></port></ports></host></nmaprun>'
    ).encode()


def test_multiple_hostnames_accumulate_and_dedup(session: Session) -> None:
    # scan A: one hostname; scan B: a second (plus the first again)
    ingest_scan(session, _scan("10.0.0.1", ["a.example"]), "a.xml", "nmap")
    ingest_scan(session, _scan("10.0.0.1", ["b.example", "a.example"]), "b.xml", "nmap")
    # re-ingest A again to prove dedup on repeat
    ingest_scan(session, _scan("10.0.0.1", ["a.example"]), "a.xml", "nmap")

    host = session.exec(select(Host).where(Host.ip == "10.0.0.1")).one()
    assert host.id is not None

    names = _hostnames_for(session, host.id)
    assert sorted(names) == ["a.example", "b.example"]  # both kept, no overwrite

    # exactly one link per (host, hostname) — no duplicates
    links = session.exec(
        select(HostHostname).where(HostHostname.host_id == host.id)
    ).all()
    assert len(links) == 2
