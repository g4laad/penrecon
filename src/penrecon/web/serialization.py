"""Page-data projections, separate from persistence and query-only fields."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.encoders import jsonable_encoder

from penrecon.queries import annotations as annotation_queries
from penrecon.queries import credentials as credential_queries
from penrecon.queries import diff as diff_queries
from penrecon.queries import inventory as inventory_queries
from penrecon.queries import operations as operation_queries
from penrecon.queries import search as search_queries
from penrecon.history import HostTimeline, TimelineEntry
from penrecon.models import Annotation, Host, Note, OperationLog, Scan


def _fields(value: object, *names: str) -> dict[str, object]:
    return {name: encode_page(getattr(value, name)) for name in names}


def host_credential(credential: credential_queries.HostCredentialView) -> dict[str, object]:
    """Encode the purpose-specific credential projection for one displayed host."""
    return {
        **_fields(credential, "id", "kind", "username", "secret", "notes"),
        "hosts": [
            {"host_id": host.host_id}
            for host in credential.hosts
        ],
        "services": [
            _fields(service, "service_id", "host_id", "port", "proto", "name")
            for service in credential.services
        ],
    }


def encode_page(value: object) -> object:
    """Encode only the fields used by page consumers, including nested objects."""
    return jsonable_encoder(value, custom_encoder=_ENCODERS)


_ENCODERS: dict[type[object], Callable[[Any], object]] = {
    Host: lambda host: _fields(host, "id", "ip", "first_seen", "last_seen"),
    Annotation: lambda ann: _fields(ann, "status", "tags"),
    Note: lambda note: _fields(note, "id", "title", "body_md", "updated_at"),
    Scan: lambda scan: _fields(scan, "id", "filename", "tool", "imported_at", "host_count"),
    OperationLog: lambda operation: _fields(
        operation, "id", "started_at", "ended_at", "source", "destination", "tool",
        "user_context", "command", "output", "description", "comments", "tags",
        "attachment_name", "created_at", "updated_at",
    ),
    operation_queries.OperationSummary: lambda operation: _fields(
        operation, "id", "started_at", "destination", "tool", "command",
    ),
    credential_queries.CredentialSummary: lambda credential: _fields(
        credential, "id", "kind", "username", "notes_preview", "host_count", "service_count",
    ),
    credential_queries.CredentialView: lambda credential: _fields(
        credential, "id", "kind", "username", "secret", "notes", "created_at",
        "hosts", "services",
    ),
    inventory_queries.HostRow: lambda row: _fields(
        row, "id", "ip", "hostnames", "open_count", "status", "tags",
        "open_services", "change", "triaged",
    ),
    search_queries.SearchResults: lambda results: _fields(results, "hosts", "notes", "credentials"),
    annotation_queries.NoteHit: lambda note: _fields(note, "href", "where", "title", "preview"),
    diff_queries.DiffResult: lambda result: {
        "scan_a": _fields(result.scan_a, "id", "filename"),
        "scan_b": _fields(result.scan_b, "id", "filename"),
        "entries": encode_page(result.entries),
    },
    HostTimeline: lambda timeline: _fields(
        timeline, "entries", "total", "page", "pages", "show_unchanged", "latest_change",
    ),
    TimelineEntry: lambda entry: _fields(
        entry, "id", "source", "scan_id", "filename", "tool", "occurred_at", "time_source",
        "first_seen", "coverage_known", "changes", "not_reported",
    ),
}
