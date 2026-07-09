from __future__ import annotations

from penrecon.parsers import nmap
from tests.fixtures import SCAN_A


def test_parse_nmap_basic() -> None:
    hosts = nmap.parse(SCAN_A.encode())
    assert len(hosts) == 1
    h = hosts[0]
    assert h.ip == "10.0.0.1"
    assert h.hostnames == ["a.example"]
    ports = {p.port: p for p in h.ports}
    assert set(ports) == {22, 80}
    assert ports[22].service_name == "ssh"
    assert ports[22].product == "OpenSSH"
    assert ports[22].version == "8.9"
    assert ports[80].service_name == "http"
