"""SQLModel tables for penrecon.

Scans are immutable snapshots of Observations. Current scan state and per-host
scan differences are projected transactionally from chronological evidence.
Annotations hang off stable entity identities (host / service / hostname) and
are never touched by ingest. Manual service overrides remain separate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, CheckConstraint, Column, ForeignKeyConstraint, Text, UniqueConstraint
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(UTC)


class Status(StrEnum):
    new = "new"
    reviewed = "reviewed"
    interesting = "interesting"
    exploited = "exploited"


class ObsState(StrEnum):
    open = "open"
    closed = "closed"
    filtered = "filtered"
    unfiltered = "unfiltered"
    open_filtered = "open|filtered"
    closed_filtered = "closed|filtered"


class Engagement(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    name: str
    description: str = ""
    created_at: datetime = Field(default_factory=_now)


class EngagementOwned(SQLModel):
    engagement_id: str = Field(foreign_key="engagement.id", ondelete="CASCADE", index=True)


class Scan(EngagementOwned, table=True):
    __table_args__ = (UniqueConstraint("engagement_id", "id"),)
    id: int | None = Field(default=None, primary_key=True)
    filename: str
    tool: str
    source_format: str
    imported_at: datetime = Field(default_factory=_now)
    host_count: int = 0
    raw_path: str | None = None


class Host(EngagementOwned, table=True):
    __table_args__ = (
        UniqueConstraint("engagement_id", "id"),
        UniqueConstraint("engagement_id", "ip"),
    )
    id: int | None = Field(default=None, primary_key=True)
    ip: str = Field(index=True)
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)


class Hostname(EngagementOwned, table=True):
    __table_args__ = (
        UniqueConstraint("engagement_id", "id"),
        UniqueConstraint("engagement_id", "name"),
    )
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)


class HostHostname(EngagementOwned, table=True):
    __tablename__ = "host_hostname"
    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "hostname_id"], ["hostname.engagement_id", "hostname.id"], ondelete="CASCADE"),
    )
    host_id: int = Field(primary_key=True)
    hostname_id: int = Field(primary_key=True)
    last_seen: datetime = Field(default_factory=_now)
    hidden: bool = False  # manually deleted; sticky across re-scans


class Service(EngagementOwned, table=True):
    """Stable service identity. Annotations point here.

    Manual overrides (m_*) win over the latest Observation for display, so a
    hand-corrected value survives re-scans. Deleting a service is a real delete
    (row + its notes); a later scan re-creates it fresh.
    """

    __table_args__ = (
        UniqueConstraint("engagement_id", "id"),
        UniqueConstraint("engagement_id", "host_id", "port", "proto"),
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
    )
    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(index=True)
    port: int
    proto: str
    m_state: ObsState | None = None
    m_service_name: str | None = None
    m_product: str | None = None
    m_version: str | None = None


class Observation(EngagementOwned, table=True):
    """One (host, port, proto) as seen by one scan. The snapshot record."""

    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "scan_id"], ["scan.engagement_id", "scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
    )
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    host_id: int = Field(index=True)
    port: int
    proto: str
    state: ObsState = ObsState.open
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    observed_at: datetime = Field(default_factory=_now)


class HostScanEvidence(EngagementOwned, table=True):
    """Immutable scan-only evidence, including hosts with no reported ports.

    Additive table: existing observations and raw files remain untouched.
    Coverage stores compact ranges, never an assumption about omitted ports.
    """

    __tablename__ = "host_scan_evidence"
    __table_args__ = (
        UniqueConstraint("engagement_id", "scan_id", "host_id"),
        ForeignKeyConstraint(["engagement_id", "scan_id"], ["scan.engagement_id", "scan.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
    )
    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(index=True)
    host_id: int = Field(index=True)
    scanned_at: datetime | None = None
    coverage: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    ports: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))


class HostScanState(EngagementOwned, table=True):
    """Persisted scan-only current state; manual overrides remain on Service."""

    __tablename__ = "host_scan_state"
    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
    )
    host_id: int = Field(primary_key=True)
    latest: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    change: str = ""


class HostScanDelta(EngagementOwned, table=True):
    """One persisted oldest-first comparison per host and scan."""

    __tablename__ = "host_scan_delta"
    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "scan_id"], ["scan.engagement_id", "scan.id"], ondelete="CASCADE"),
    )
    host_id: int = Field(primary_key=True)
    scan_id: int = Field(primary_key=True)
    entry: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))


class ManualServiceEvent(EngagementOwned, table=True):
    """Append-only service value snapshots, independent of service lifetime.

    Only future manual actions are recorded. The scalar JSON snapshots never
    resolve against mutable services or observations when read.
    """

    __tablename__ = "manual_service_event"
    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
        CheckConstraint("kind IN ('added', 'changed', 'removed')", name="manual_service_event_kind"),
    )
    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(index=True)
    port: int
    proto: str
    occurred_at: datetime = Field(default_factory=_now, index=True)
    kind: str
    before: dict[str, str | None] | None = Field(default=None, sa_column=Column(JSON))
    after: dict[str, str | None] | None = Field(default=None, sa_column=Column(JSON))
    before_overrides: dict[str, str | None] | None = Field(default=None, sa_column=Column(JSON))
    after_overrides: dict[str, str | None] | None = Field(default=None, sa_column=Column(JSON))


class Annotation(EngagementOwned, table=True):
    """Triage state (status/tags) on a host or service. Never modified by
    ingest. Freeform notes live in :class:`Note`.

    Exactly one of host_id/service_id is set (CHECK). Each is UNIQUE, so a
    host/service has at most one annotation; SQLite treats the NULL side as
    distinct, so the other-kind rows don't collide. Real FKs with ON DELETE
    CASCADE: deleting the host/service drops its annotation automatically."""

    __table_args__ = (
        CheckConstraint(
            "(host_id IS NULL) <> (service_id IS NULL)", name="annotation_one_target"
        ),
        UniqueConstraint("engagement_id", "host_id"),
        UniqueConstraint("engagement_id", "service_id"),
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "service_id"], ["service.engagement_id", "service.id"], ondelete="CASCADE"),
    )
    id: int | None = Field(default=None, primary_key=True)
    host_id: int | None = None
    service_id: int | None = None
    status: Status = Status.new
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    updated_at: datetime = Field(default_factory=_now)


class Note(EngagementOwned, table=True):
    """A titled freeform note on a host. Any number per host. Pure user data —
    like annotations, ingest never touches it; the FK's ON DELETE CASCADE drops
    a host's notes with the host."""

    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
    )
    id: int | None = Field(default=None, primary_key=True)
    host_id: int = Field(index=True)
    title: str
    body_md: str = ""
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class OperationLog(EngagementOwned, table=True):
    __tablename__ = "operation_log"

    id: int | None = Field(default=None, primary_key=True)
    started_at: datetime | None = Field(default=None, index=True)
    ended_at: datetime | None = None
    source: str = ""
    destination: str = ""
    tool: str = ""
    user_context: str = ""
    command: str = Field(sa_column=Column(Text))
    output: str = Field(default="", sa_column=Column(Text))
    description: str = Field(default="", sa_column=Column(Text))
    comments: str = Field(default="", sa_column=Column(Text))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    attachment_name: str | None = None
    attachment_path: str | None = None
    attachment_media_type: str | None = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class CredKind(StrEnum):
    password = "password"
    hash = "hash"
    key = "key"
    token = "token"
    other = "other"


class Credential(EngagementOwned, table=True):
    """A found secret. Linked M:N to any number of hosts and services (none is
    fine). Pure user data — like annotations, ingest never touches it."""

    __table_args__ = (UniqueConstraint("engagement_id", "id"),)
    id: int | None = Field(default=None, primary_key=True)
    kind: CredKind = CredKind.password
    username: str = ""
    secret: str = ""  # password / hash / key material / token
    notes: str = ""
    created_at: datetime = Field(default_factory=_now)


class CredentialHost(EngagementOwned, table=True):
    __tablename__ = "credential_host"
    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "credential_id"], ["credential.engagement_id", "credential.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "host_id"], ["host.engagement_id", "host.id"], ondelete="CASCADE"),
    )
    credential_id: int = Field(primary_key=True)
    host_id: int = Field(primary_key=True)


class CredentialService(EngagementOwned, table=True):
    __tablename__ = "credential_service"
    __table_args__ = (
        ForeignKeyConstraint(["engagement_id", "credential_id"], ["credential.engagement_id", "credential.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(["engagement_id", "service_id"], ["service.engagement_id", "service.id"], ondelete="CASCADE"),
    )
    credential_id: int = Field(primary_key=True)
    service_id: int = Field(primary_key=True)


# Register on SQLModel Session so every application session, including isolated
# test sessions, maintains projections. Replay imports remain lazy to avoid the
# models/history/db import cycle.
from penrecon.projections import register_session_hooks

register_session_hooks()
