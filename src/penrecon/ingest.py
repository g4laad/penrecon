"""Ingest a parsed scan into the DB. Shared by the web upload and the CLI.

Upserts host/hostname/service identities and appends immutable Observation
rows. Never touches Annotation/Attachment.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session, select

from penrecon.models import (
    Host,
    Hostname,
    HostHostname,
    Observation,
    ObsState,
    Scan,
    Service,
)
from penrecon.parsers import HostResult, get_parser


def _obs_state(raw: str) -> ObsState:
    try:
        return ObsState(raw)
    except ValueError:
        return ObsState.filtered


def _upsert_host(session: Session, ip: str, now: datetime) -> Host:
    host = session.exec(select(Host).where(Host.ip == ip)).first()
    if host is None:
        host = Host(ip=ip, first_seen=now, last_seen=now)
        session.add(host)
        session.flush()
    else:
        host.last_seen = now
    return host


def _upsert_hostname(session: Session, host_id: int, name: str, now: datetime) -> None:
    hn = session.exec(select(Hostname).where(Hostname.name == name)).first()
    if hn is None:
        hn = Hostname(name=name)
        session.add(hn)
        session.flush()
    assert hn.id is not None
    link = session.exec(
        select(HostHostname).where(
            HostHostname.host_id == host_id, HostHostname.hostname_id == hn.id
        )
    ).first()
    if link is None:
        session.add(HostHostname(host_id=host_id, hostname_id=hn.id, last_seen=now))
    else:
        link.last_seen = now


def _upsert_service(session: Session, host_id: int, port: int, proto: str) -> None:
    svc = session.exec(
        select(Service).where(
            Service.host_id == host_id, Service.port == port, Service.proto == proto
        )
    ).first()
    if svc is None:
        session.add(Service(host_id=host_id, port=port, proto=proto))
    elif svc.hidden:
        svc.hidden = False  # a re-scan resurrects a manually-deleted service (mistakes happen)


def _store_host(session: Session, scan_id: int, hr: HostResult, now: datetime) -> None:
    host = _upsert_host(session, hr.ip, now)
    assert host.id is not None
    for name in hr.hostnames:
        if name:
            _upsert_hostname(session, host.id, name, now)
    for p in hr.ports:
        _upsert_service(session, host.id, p.port, p.proto)
        session.add(
            Observation(
                scan_id=scan_id,
                host_id=host.id,
                port=p.port,
                proto=p.proto,
                state=_obs_state(p.state),
                service_name=p.service_name,
                product=p.product,
                version=p.version,
                extra=p.extra,
                observed_at=now,
            )
        )


def ingest_scan(session: Session, data: bytes, filename: str, tool: str) -> Scan:
    parser = get_parser(tool)
    result = parser(data)
    now = datetime.now(UTC)

    scan = Scan(
        filename=filename,
        tool=tool,
        source_format=tool,
        imported_at=now,
        host_count=len(result),
    )
    session.add(scan)
    session.flush()
    assert scan.id is not None

    for hr in result:
        _store_host(session, scan.id, hr, now)

    session.commit()
    session.refresh(scan)
    return scan
