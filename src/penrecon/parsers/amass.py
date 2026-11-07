"""Amass subs -names -ip text and legacy enum -json JSON/JSONL imports."""

from __future__ import annotations

import json
import re
from typing import Any

from penrecon.inventory import normalize_hostname, normalize_ip
from penrecon.parsers import HostResult, ScanResult

_ANSI_COLOR = re.compile(r"\x1b\[[0-9;]*m")
_IP_REQUIRED = (
    "Amass import requires hostname/IP mappings; export with "
    "amass subs -d DOMAIN -names -ip -nocolor -o amass.txt"
)


def _json_records(text: str) -> list[Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        records: list[Any] = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid Amass JSON on line {number}: {exc.msg}") from exc
        return records
    return value if isinstance(value, list) else [value]


def parse(data: bytes) -> ScanResult:
    text = _ANSI_COLOR.sub("", data.decode("utf-8-sig")).strip()
    hosts: dict[str, HostResult] = {}

    def add(name: str, addresses: list[str], location: str) -> None:
        try:
            name = normalize_hostname(name)
        except ValueError as exc:
            raise ValueError(f"Invalid Amass hostname at {location}") from exc
        for address in addresses:
            try:
                ip = normalize_ip(address)
            except ValueError as exc:
                raise ValueError(f"Invalid Amass IP address {address!r} at {location}") from exc
            host = hosts.setdefault(ip, HostResult(ip=ip))
            if name not in host.hostnames:
                host.hostnames.append(name)

    if text.startswith(("{", "[")):
        for number, record in enumerate(_json_records(text), 1):
            location = f"record {number}"
            if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                raise ValueError(f"Expected an Amass name/addresses object at {location}")
            entries = record.get("addresses")
            # Passive legacy output can contain unresolved names. Never resolve
            # these during import or create hosts with a hostname as their IP.
            if entries is None:
                entries = []
            if not isinstance(entries, list):
                raise ValueError(f"Expected an Amass addresses list at {location}")
            addresses: list[str] = []
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("ip"), str):
                    raise ValueError(f"Expected an Amass address object with ip at {location}")
                addresses.append(entry["ip"])
            add(record["name"], addresses, location)
    else:
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"{_IP_REQUIRED} (line {number})")
            add(parts[0], parts[1].split(","), f"line {number}")

    if not hosts:
        raise ValueError(_IP_REQUIRED)
    return list(hosts.values())
