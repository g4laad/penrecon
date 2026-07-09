"""SQLModel tables for penrecon.

Scans are immutable snapshots of Observations. Current state is derived by
latest-observation-wins per (host, port, proto). Annotations hang off stable
entity identities (host / service / hostname) and are never touched by ingest.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Column, UniqueConstraint
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(UTC)


class TargetType(StrEnum):
    host = "host"
    service = "service"
    hostname = "hostname"


class Status(StrEnum):
    new = "new"
    reviewed = "reviewed"
    interesting = "interesting"
    exploited = "exploited"


class ObsState(StrEnum):
    open = "open"
    closed = "closed"
    filtered = "filtered"


class Scan(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    filename: str
    tool: str
    source_format: str
    imported_at: datetime = Field(default_factory=_now)
    host_count: int = 0
    raw_path: str | None = None


class Host(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    ip: str = Field(unique=True, index=True)
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)


class Hostname(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(unique=True, index=True)


class HostHostname(SQLModel, table=True):
    __tablename__ = "host_hostname"
    host_id: int = Field(foreign_key="host.id", primary_key=True)
    hostname_id: int = Field(foreign_key="hostname.id", primary_key=True)
    last_seen: datetime = Field(default_factory=_now)
    hidden: bool = False  # manually deleted; sticky across re-scans


class Service(SQLModel, table=True):
    """Stable service identity. Annotations point here.

    Manual overrides (m_*) win over the latest Observation for display, so a
    hand-corrected value survives re-scans. Deleting a service is a real delete
    (row + its notes); a later scan re-creates it fresh.
    """

    __table_args__ = (UniqueConstraint("host_id", "port", "proto"),)
    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port: int
    proto: str
    m_state: ObsState | None = None
    m_service_name: str | None = None
    m_product: str | None = None
    m_version: str | None = None


class Observation(SQLModel, table=True):
    """One (host, port, proto) as seen by one scan. The snapshot record."""

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    host_id: int = Field(foreign_key="host.id", index=True)
    port: int
    proto: str
    state: ObsState = ObsState.open
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=_now)


class Annotation(SQLModel, table=True):
    """Triage state (status/tags) on an entity. Never modified by ingest.
    Freeform notes live in :class:`Note`."""

    __table_args__ = (UniqueConstraint("target_type", "target_id"),)
    id: int | None = Field(default=None, primary_key=True)
    target_type: TargetType
    target_id: int
    status: Status = Status.new
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    updated_at: datetime = Field(default_factory=_now)


class Note(SQLModel, table=True):
    """A titled freeform note on a host. Any number per target. Pure user
    data — like annotations, ingest never touches it; deleting a host deletes
    its notes."""

    id: int | None = Field(default=None, primary_key=True)
    target_type: TargetType
    target_id: int
    title: str
    body_md: str = ""
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class CredKind(StrEnum):
    password = "password"
    hash = "hash"
    key = "key"
    token = "token"
    other = "other"


class Credential(SQLModel, table=True):
    """A found secret. Linked M:N to any number of hosts and services (none is
    fine). Pure user data — like annotations, ingest never touches it."""

    id: int | None = Field(default=None, primary_key=True)
    kind: CredKind = CredKind.password
    username: str = ""
    secret: str = ""  # password / hash / key material / token
    notes: str = ""
    created_at: datetime = Field(default_factory=_now)


class CredentialHost(SQLModel, table=True):
    __tablename__ = "credential_host"
    credential_id: int = Field(foreign_key="credential.id", primary_key=True)
    host_id: int = Field(foreign_key="host.id", primary_key=True)


class CredentialService(SQLModel, table=True):
    __tablename__ = "credential_service"
    credential_id: int = Field(foreign_key="credential.id", primary_key=True)
    service_id: int = Field(foreign_key="service.id", primary_key=True)
