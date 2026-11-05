"""Parser registry. Each parser turns raw tool output bytes into a normalized
ScanResult that ingest knows how to store.

Implemented parsers handle nmap XML and Amass hostname/IP exports.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PortResult:
    port: int
    proto: str
    state: str = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)


ScanResult = list[HostResult]
Parser = Callable[[bytes], ScanResult]

from penrecon.parsers import amass, nmap  # noqa: E402

PARSERS: dict[str, Parser] = {
    "nmap": nmap.parse,
    "amass": amass.parse,
}


def get_parser(tool: str) -> Parser:
    try:
        return PARSERS[tool]
    except KeyError:
        raise ValueError(f"unknown tool {tool!r}; known: {', '.join(sorted(PARSERS))}")
