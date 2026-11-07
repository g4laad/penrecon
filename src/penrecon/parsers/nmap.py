"""Parse nmap XML into unique host identities and conservative scan evidence.

Duplicate host records retain explicit ports (last occurrence wins per identity).
Conflicting coverage summaries are discarded rather than implying port closure.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from xml.etree import ElementTree as ET

from penrecon.inventory import normalize_hostname, normalize_ip, normalize_protocol
from penrecon.models import ObsState
from penrecon.parsers import HostResult, PortResult, ScanResult


def _state(value: str) -> str:
    try:
        return ObsState(value).value
    except ValueError as exc:
        raise ValueError(f"Unknown nmap port state {value!r}") from exc


def _port_set(value: str) -> set[int] | None:
    ports: set[int] = set()
    try:
        for part in value.split(","):
            ends = part.strip().split("-")
            if len(ends) not in (1, 2):
                return None
            start, end = int(ends[0]), int(ends[-1])
            if not 0 <= start <= end <= 65535:
                return None
            ports.update(range(start, end + 1))
    except ValueError:
        return None
    return ports


def _ranges(ports: set[int]) -> list[list[int]]:
    result: list[list[int]] = []
    for port in sorted(ports):
        if result and port == result[-1][1] + 1:
            result[-1][1] = port
        else:
            result.append([port, port])
    return result


def _count(value: str | None) -> int | None:
    try:
        result = int(value or "")
        return result if result >= 0 else None
    except ValueError:
        return None


def _timestamp(*values: str | None) -> datetime | None:
    for value in values:
        try:
            if value is not None:
                return datetime.fromtimestamp(float(value), UTC)
        except (ValueError, OverflowError, OSError):
            continue
    return None


def _coverage(root: ET.Element, host: ET.Element, ports: list[PortResult]) -> dict[str, Any]:
    scanned: dict[str, set[int]] = {}
    invalid: set[str] = set()
    for info in root.findall("scaninfo"):
        proto = normalize_protocol(info.get("protocol", "")) if info.get("protocol", "").strip() else ""
        selected = _port_set(info.get("services", ""))
        count = _count(info.get("numservices"))
        if not proto or selected is None or (count is not None and len(selected) != count):
            invalid.add(proto)
            continue
        scanned.setdefault(proto, set()).update(selected)
    for proto in invalid:
        scanned.pop(proto, None)
    explicit = {(port.proto, port.port) for port in ports}
    candidates = {(proto, port) for proto, values in scanned.items() for port in values} - explicit
    assigned: dict[tuple[str, int], str] = {}
    conflicted: set[tuple[str, int]] = set()
    outstanding: list[tuple[str, int]] = []
    for group in host.findall("ports/extraports"):
        state = _state(group.get("state", ""))
        total = _count(group.get("count"))
        if total is None:
            outstanding.append(("unknown", 1))
            continue
        named: set[tuple[str, int]] = set()
        for reason in group.findall("extrareasons"):
            proto = normalize_protocol(reason.get("proto", "")) if reason.get("proto", "").strip() else ""
            values = _port_set(reason.get("ports", ""))
            count = _count(reason.get("count"))
            if not proto or values is None or count != len(values):
                continue
            keys = {(proto, port) for port in values}
            if keys & explicit or (proto in scanned and not values <= scanned[proto]):
                continue
            named.update(keys)
        if len(named) > total:
            outstanding.append(("unknown", 1))
            continue
        for key in named:
            if key in assigned and assigned[key] != state:
                conflicted.add(key)
            assigned[key] = state
        if total > len(named):
            outstanding.append((state, total - len(named)))
    # An aggregate count only identifies omitted ports when every remaining
    # covered port is accounted for and all have one unambiguous state.
    remaining = candidates - assigned.keys()
    states = {state for state, count in outstanding if count}
    if len(states) == 1 and len(remaining) == sum(count for _, count in outstanding):
        state = next(iter(states))
        if state in {"closed", "filtered"}:
            assigned.update(dict.fromkeys(remaining, state))
    groups: dict[tuple[str, str], set[int]] = {}
    for (proto, port), state in assigned.items():
        if (proto, port) not in conflicted and state in {"closed", "filtered"}:
            groups.setdefault((proto, state), set()).add(port)
    return {
        "known": bool(scanned),
        "ports": {proto: _ranges(values) for proto, values in scanned.items()},
        "states": [
            {"proto": proto, "state": state, "ports": _ranges(values)}
            for (proto, state), values in sorted(groups.items())
        ],
    }


def parse(data: bytes) -> ScanResult:
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("Invalid nmap XML") from exc
    if root.tag != "nmaprun":
        raise ValueError("Expected nmap XML exported with -oX")
    hosts: dict[str, HostResult] = {}
    finished = root.find("runstats/finished")
    for host in root.findall("host"):
        address = next(
            (node.get("addr") for node in host.findall("address") if node.get("addrtype") in {"ipv4", "ipv6"}),
            None,
        )
        if address is None:
            continue
        address = normalize_ip(address)
        ports: list[PortResult] = []
        for node in host.findall("ports/port"):
            number = _count(node.get("portid"))
            proto = node.get("protocol")
            state = node.find("state")
            if number is None or number > 65535 or not proto or state is None or not state.get("state"):
                raise ValueError("Invalid nmap port evidence")
            service = node.find("service")
            extra: dict[str, Any] = {}
            scripts = node.findall("script")
            if scripts:
                extra["scripts"] = {script.get("id", ""): script.get("output", "") for script in scripts}
            ports.append(PortResult(
                port=number,
                proto=normalize_protocol(proto),
                state=_state(state.get("state", "")),
                service_name=service.get("name") or None if service is not None else None,
                product=service.get("product") or None if service is not None else None,
                version=service.get("version") or None if service is not None else None,
                extra=extra,
            ))
        ports = list({(port.port, port.proto): port for port in ports}.values())
        names = list(dict.fromkeys(
            normalize_hostname(node.get("name", ""))
            for node in host.findall("hostnames/hostname") if node.get("name")
        ))
        result = HostResult(
            ip=address,
            hostnames=names,
            ports=ports,
            scanned_at=_timestamp(host.get("starttime"), root.get("start"), host.get("endtime"), finished.get("time") if finished is not None else None),
            coverage=_coverage(root, host, ports),
        )
        previous = hosts.get(address)
        if previous is not None:
            result.hostnames = list(dict.fromkeys(previous.hostnames + names))
            result.ports = list({
                (port.port, port.proto): port for port in previous.ports + ports
            }.values())
            times = [value for value in (previous.scanned_at, result.scanned_at) if value is not None]
            result.scanned_at = max(times) if times else None
            if previous.coverage != result.coverage:
                result.coverage = {}
        hosts[address] = result
    return list(hosts.values())
