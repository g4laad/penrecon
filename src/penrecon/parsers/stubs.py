"""Placeholder parsers for tools not yet implemented."""

from __future__ import annotations

from penrecon.parsers import Parser, ScanResult


def not_implemented(tool: str) -> Parser:
    def _parse(_data: bytes) -> ScanResult:
        raise NotImplementedError(f"{tool} parser not implemented yet")

    return _parse
