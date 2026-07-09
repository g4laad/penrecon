"""Minimal nmap XML fixtures for tests."""

from __future__ import annotations


def _host(ip: str, ports: str, hostname: str = "a.example") -> str:
    return f"""
  <host><status state="up"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <hostnames><hostname name="{hostname}" type="user"/></hostnames>
    <ports>{ports}</ports>
  </host>"""


def _port(portid: int, name: str, state: str = "open", product: str = "", version: str = "") -> str:
    return f"""
      <port protocol="tcp" portid="{portid}">
        <state state="{state}"/>
        <service name="{name}" product="{product}" version="{version}" method="probed"/>
      </port>"""


# Scan A: 22 ssh OpenSSH 8.9, 80 http Apache 2.4.1
SCAN_A = f"""<?xml version="1.0"?><nmaprun scanner="nmap">{
    _host("10.0.0.1",
          _port(22, "ssh", "open", "OpenSSH", "8.9")
          + _port(80, "http", "open", "Apache httpd", "2.4.1"))
}</nmaprun>"""

# Scan B: 22 ssh OpenSSH 9.0 (version changed), 80 closed, 443 https added
SCAN_B = f"""<?xml version="1.0"?><nmaprun scanner="nmap">{
    _host("10.0.0.1",
          _port(22, "ssh", "open", "OpenSSH", "9.0")
          + _port(80, "http", "closed", "Apache httpd", "2.4.1")
          + _port(443, "https", "open", "nginx", "1.25"))
}</nmaprun>"""
