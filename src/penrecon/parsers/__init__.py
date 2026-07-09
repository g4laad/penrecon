"""Parser registry. Each parser turns raw tool output bytes into a normalized
ScanResult that ingest knows how to store.

Only nmap is implemented in v1; the rest are registered stubs so the shape of
the plugin layer is fixed and adding one later is a single file.
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

from penrecon.parsers import nmap, stubs  # noqa: E402

PARSERS: dict[str, Parser] = {
    "nmap": nmap.parse,
    "masscan": stubs.not_implemented("masscan"),
    "rustscan": stubs.not_implemented("rustscan"),
    "httpx": stubs.not_implemented("httpx"),
    "nuclei": stubs.not_implemented("nuclei"),
    "whatweb": stubs.not_implemented("whatweb"),
    "subfinder": stubs.not_implemented("subfinder"),
    "amass": stubs.not_implemented("amass"),
    "dnsx": stubs.not_implemented("dnsx"),
}


def get_parser(tool: str) -> Parser:
    try:
        return PARSERS[tool]
    except KeyError:
        raise ValueError(f"unknown tool {tool!r}; known: {', '.join(sorted(PARSERS))}")
