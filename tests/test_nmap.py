from __future__ import annotations

import pytest

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


@pytest.mark.parametrize(
    "evidence",
    [
        '<port protocol="tcp" portid="80"><state state="mystery"/></port>',
        '<extraports state="mystery" count="1"/>',
    ],
)
def test_parse_rejects_unknown_nmap_states(evidence: str) -> None:
    data = (
        '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
        f"<ports>{evidence}</ports></host></nmaprun>"
    ).encode()
    with pytest.raises(ValueError, match="mystery"):
        nmap.parse(data)


def test_duplicate_hosts_merge_explicit_evidence_without_inventing_coverage() -> None:
    data = b"""<nmaprun>
      <scaninfo protocol="TCP" services="22,80" numservices="2"/>
      <host starttime="100"><address addr="2001:0DB8::0001" addrtype="ipv6"/>
        <hostnames><hostname name=" API.Example. "/></hostnames>
        <ports><port protocol=" TCP " portid="22"><state state="open"/></port>
          <extraports state="closed" count="1"/></ports>
      </host>
      <host starttime="200"><address addr="2001:db8::1" addrtype="ipv6"/>
        <hostnames><hostname name="api.example"/><hostname name="other.example"/></hostnames>
        <ports><port protocol="tcp" portid="80"><state state="open|filtered"/></port>
          <extraports state="filtered" count="1"/></ports>
      </host>
    </nmaprun>"""
    hosts = nmap.parse(data)
    assert len(hosts) == 1
    assert hosts[0].ip == "2001:db8::1"
    assert hosts[0].hostnames == ["api.example", "other.example"]
    assert [(port.port, port.proto, port.state) for port in hosts[0].ports] == [
        (22, "tcp", "open"),
        (80, "tcp", "open|filtered"),
    ]
    assert hosts[0].coverage.get("states", []) == []


def test_ambiguous_aggregate_states_do_not_imply_closure() -> None:
    data = b"""<nmaprun>
      <scaninfo protocol="tcp" services="22-23" numservices="2"/>
      <host><address addr="10.0.0.1" addrtype="ipv4"/>
        <ports><extraports state="open|filtered" count="2"/></ports>
      </host>
    </nmaprun>"""
    host = nmap.parse(data)[0]
    assert host.coverage["known"] is True
    assert host.coverage["states"] == []
