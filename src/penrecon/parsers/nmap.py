"""nmap XML (`-oX`) parser, backed by python-libnmap."""

from __future__ import annotations

from typing import Any

from libnmap.parser import NmapParser

from penrecon.parsers import HostResult, PortResult, ScanResult


def parse(data: bytes) -> ScanResult:
    report = NmapParser.parse_fromstring(data.decode("utf-8", errors="replace"))
    hosts: ScanResult = []
    for h in report.hosts:
        ports: list[PortResult] = []
        for svc in h.services:
            banner = svc.banner_dict  # product / version / extrainfo when -sV
            extra: dict[str, Any] = {}
            if svc.scripts_results:
                extra["scripts"] = {
                    s.get("id", ""): s.get("output", "") for s in svc.scripts_results
                }
            ports.append(
                PortResult(
                    port=int(svc.port),
                    proto=svc.protocol,
                    state=svc.state,
                    service_name=svc.service or None,
                    product=banner.get("product"),
                    version=banner.get("version"),
                    extra=extra,
                )
            )
        hosts.append(HostResult(ip=h.address, hostnames=list(h.hostnames), ports=ports))
    return hosts
