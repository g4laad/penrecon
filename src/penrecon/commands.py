"""Inventory mutations: validate before staging, preserve evidence, commit in callers.

Triage status and credential kind are free classifications, not lifecycle graphs.
Blank service text/state overrides deliberately reset to scan inheritance.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum

from sqlmodel import Session, select

from penrecon import queries
from penrecon.history import Overrides, State
from penrecon.inventory import normalize_protocol
from penrecon.models import (
    CredKind, Credential, CredentialHost, CredentialService, Host,
    ManualServiceEvent, Observation, ObsState, Service,
)


class InvalidCommand(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class ServiceIdentity:
    port: int
    proto: str

    @classmethod
    def parse(cls, port: int, proto: str) -> ServiceIdentity:
        if not 0 <= port <= 65535:
            raise InvalidCommand("port", "Port must be between 0 and 65535.")
        try:
            normalized = normalize_protocol(proto)
        except ValueError as exc:
            raise InvalidCommand("proto", "Choose TCP, UDP, or SCTP.") from exc
        if normalized not in {"tcp", "udp", "sctp"}:
            raise InvalidCommand("proto", "Choose TCP, UDP, or SCTP.")
        return cls(port, normalized)


@dataclass(frozen=True)
class ServiceOverrides:
    state: ObsState | None
    service_name: str | None
    product: str | None
    version: str | None

    @classmethod
    def parse(cls, state: str, service_name: str, product: str, version: str, *, creating: bool = False) -> ServiceOverrides:
        clean_state = state.strip()
        try:
            parsed = ObsState(clean_state) if clean_state else ObsState.open if creating else None
        except ValueError as exc:
            raise InvalidCommand("state", "Choose a supported service state, or leave blank to inherit scan evidence.") from exc
        return cls(parsed, service_name.strip() or None, product.strip() or None, version.strip() or None)

    def apply(self, service: Service) -> None:
        service.m_state = self.state
        service.m_service_name = self.service_name
        service.m_product = self.product
        service.m_version = self.version


ServiceSnapshot = tuple[State, Overrides]


def _snapshot(service: Service, observation: Observation | None) -> ServiceSnapshot:
    return queries.service_state(service, observation), queries.service_overrides(service)


def _record(session: Session, service: Service, before: ServiceSnapshot | None, after: ServiceSnapshot | None) -> None:
    if before == after:
        return
    session.add(ManualServiceEvent(
        engagement_id=service.engagement_id, host_id=service.host_id,
        port=service.port, proto=service.proto,
        kind="added" if before is None else "removed" if after is None else "changed",
        before=asdict(before[0]) if before is not None else None,
        after=asdict(after[0]) if after is not None else None,
        before_overrides=asdict(before[1]) if before is not None else None,
        after_overrides=asdict(after[1]) if after is not None else None,
    ))


def override_service(session: Session, service: Service, values: ServiceOverrides, observation: Observation | None, *, creating: bool = False) -> None:
    before = None if creating else _snapshot(service, observation)
    values.apply(service)
    session.add(service)
    _record(session, service, before, _snapshot(service, observation))


def remove_service(session: Session, service: Service, observation: Observation | None) -> None:
    """Delete current overrides/links, not immutable observations or action events.

    A later explicit scan discovery creates a fresh service identity.
    """
    _record(session, service, _snapshot(service, observation), None)
    session.delete(service)


@dataclass(frozen=True)
class CredentialValues:
    kind: CredKind
    username: str
    secret: str
    notes: str

    @classmethod
    def parse(cls, kind: str, username: str, secret: str, notes: str) -> CredentialValues:
        user, sec = username.strip(), secret.strip()
        if not (user or sec):
            raise InvalidCommand("username", "a credential must carry at least a username or a secret")
        try:
            classification = CredKind(kind)
        except ValueError:
            classification = CredKind.password
        return cls(classification, user, sec, notes.strip())

    def apply(self, credential: Credential) -> None:
        credential.kind = self.kind
        credential.username = self.username
        credential.secret = self.secret
        credential.notes = self.notes


class LinkOutcome(StrEnum):
    linked = "linked"
    already_linked = "already_linked"


def link_credential_host(session: Session, credential: Credential, host: Host) -> LinkOutcome:
    if credential.engagement_id != host.engagement_id:
        raise InvalidCommand("host_id", "host belongs to another engagement")
    assert credential.id is not None and host.id is not None
    if queries.get_owned(session, CredentialHost, (credential.id, host.id), engagement_id=credential.engagement_id) is not None:
        return LinkOutcome.already_linked
    session.add(CredentialHost(credential_id=credential.id, host_id=host.id, engagement_id=credential.engagement_id))
    return LinkOutcome.linked


def link_credential_service(session: Session, credential: Credential, service: Service) -> LinkOutcome:
    if credential.engagement_id != service.engagement_id:
        raise InvalidCommand("service_id", "service belongs to another engagement")
    assert credential.id is not None and service.id is not None
    if queries.get_owned(session, CredentialHost, (credential.id, service.host_id), engagement_id=credential.engagement_id) is None:
        raise InvalidCommand("service_id", "Link the service's host to this credential before linking the service.")
    if queries.get_owned(session, CredentialService, (credential.id, service.id), engagement_id=credential.engagement_id) is not None:
        return LinkOutcome.already_linked
    session.add(CredentialService(credential_id=credential.id, service_id=service.id, engagement_id=credential.engagement_id))
    return LinkOutcome.linked


def unlink_credential_host(session: Session, credential: Credential, host: Host) -> None:
    """Unlink dependent services first; re-linking the host cannot resurrect them."""
    if credential.engagement_id != host.engagement_id:
        raise InvalidCommand("host_id", "host belongs to another engagement")
    assert credential.id is not None and host.id is not None
    links = session.exec(
        select(CredentialService).where(CredentialService.engagement_id == credential.engagement_id)
        .join(Service, Service.id == CredentialService.service_id)  # type: ignore[arg-type]
        .where(CredentialService.credential_id == credential.id, Service.host_id == host.id)
    ).all()
    for link in links:
        session.delete(link)
    host_link = queries.get_owned(session, CredentialHost, (credential.id, host.id), engagement_id=credential.engagement_id)
    if host_link is not None:
        session.delete(host_link)
