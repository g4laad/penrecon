"""Public inventory projections, independent of persistence-only fields."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from penrecon.models import CredKind, ObsState, Status


class AnnotationResponse(BaseModel):
    status: Status
    tags: list[str]


class HostResponse(BaseModel):
    id: int
    ip: str
    first_seen: datetime
    last_seen: datetime


class HostRowResponse(BaseModel):
    id: int
    ip: str
    hostnames: list[str]
    open_count: int
    status: Status
    tags: list[str]
    open_services: list[tuple[int, str | None]]
    change: Literal["", "new", "changed"]
    triaged: bool


class HostsResponse(BaseModel):
    q: str
    port: str
    tag: str
    status: str
    change: str
    sort: str
    direction: str
    rows: list[HostRowResponse]
    total: int
    matched: int
    page: int
    pages: int


class InventoryResponse(HostsResponse):
    statuses: list[Status]


class ServiceStateResponse(BaseModel):
    state: str
    service_name: str | None
    product: str | None
    version: str | None


class ServiceOverridesResponse(BaseModel):
    state: str | None
    service_name: str | None
    product: str | None
    version: str | None


class ServiceResponse(ServiceStateResponse):
    service_id: int
    port: int
    proto: str
    last_seen: str
    annotation: AnnotationResponse | None
    overrides: ServiceOverridesResponse
    manual: bool


class ServicesResponse(BaseModel):
    services: list[ServiceResponse]
    svc_total: int
    page: int
    pages: int
    sort: str
    direction: str
    per: str
    f_port: str
    f_state: str
    f_service: str
    f_status: str


class PortIdentityResponse(BaseModel):
    port: int
    proto: str


class ServiceChangeResponse(PortIdentityResponse):
    kind: str
    before: ServiceStateResponse | None
    after: ServiceStateResponse | None
    before_overrides: ServiceOverridesResponse | None
    after_overrides: ServiceOverridesResponse | None


class TimelineEntryResponse(BaseModel):
    id: str
    source: str
    scan_id: int | None
    filename: str
    tool: str
    occurred_at: str
    time_source: str
    first_seen: bool
    coverage_known: bool
    changes: list[ServiceChangeResponse]
    not_reported: list[PortIdentityResponse]


class HostTimelineResponse(BaseModel):
    entries: list[TimelineEntryResponse]
    total: int
    page: int
    pages: int
    show_unchanged: bool
    latest_change: TimelineEntryResponse | None


class TimelineResponse(BaseModel):
    host_timeline: HostTimelineResponse


class HostOptionResponse(BaseModel):
    id: int
    ip: str


class HostOptionsResponse(BaseModel):
    hosts: list[HostOptionResponse]


class ServiceOptionResponse(PortIdentityResponse):
    service_id: int
    service_name: str | None


class ServiceOptionsResponse(BaseModel):
    services: list[ServiceOptionResponse]


class HostNoteResponse(BaseModel):
    id: int
    title: str
    body_md: str
    updated_at: datetime


class CredentialHostResponse(BaseModel):
    host_id: int


class HostCredentialServiceResponse(PortIdentityResponse):
    service_id: int
    host_id: int
    name: str | None


class HostCredentialResponse(BaseModel):
    id: int
    kind: CredKind
    username: str
    secret: str
    notes: str
    hosts: list[CredentialHostResponse]
    services: list[HostCredentialServiceResponse]


class HostDetailResponse(ServicesResponse):
    host: HostResponse
    statuses: list[Status]
    states: list[ObsState]
    hostnames: list[tuple[int, str]]
    host_ann: AnnotationResponse | None
    host_notes: list[HostNoteResponse]
    host_credentials: list[HostCredentialResponse]
    host_timeline: HostTimelineResponse
    kinds: list[CredKind]
