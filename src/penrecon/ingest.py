"""Ingest a parsed scan into the DB. Shared by the web upload and the CLI.

Upserts host/hostname/service identities and appends immutable Observation
rows. Never touches Annotation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlmodel import Session, select

from penrecon.db import DATA_DIR, engagement_scans_dir
from penrecon.inventory import link_hostname
from penrecon.models import (
    Host,
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


def _upsert_host(
    session: Session, ip: str, now: datetime, *, engagement_id: str
) -> Host:
    host = session.exec(
        select(Host).where(Host.engagement_id == engagement_id, Host.ip == ip)
    ).first()
    if host is None:
        host = Host(engagement_id=engagement_id, ip=ip, first_seen=now, last_seen=now)
        session.add(host)
        session.flush()
    else:
        host.last_seen = now
    return host


def _upsert_service(
    session: Session, host_id: int, port: int, proto: str, *, engagement_id: str
) -> None:
    svc = session.exec(
        select(Service).where(
            Service.engagement_id == engagement_id,
            Service.host_id == host_id, Service.port == port, Service.proto == proto
        )
    ).first()
    if svc is None:
        session.add(Service(engagement_id=engagement_id, host_id=host_id, port=port, proto=proto))
    # a deleted service is gone from the DB; this recreates it fresh when a scan
    # sees the port again


def _store_host(
    session: Session, scan_id: int, hr: HostResult, now: datetime, *, engagement_id: str
) -> None:
    host = _upsert_host(session, hr.ip, now, engagement_id=engagement_id)
    assert host.id is not None
    for name in hr.hostnames:
        if name:
            link_hostname(session, host.id, name, now, engagement_id=engagement_id)
    for p in hr.ports:
        _upsert_service(session, host.id, p.port, p.proto, engagement_id=engagement_id)
        session.add(
            Observation(
                engagement_id=engagement_id,
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


def ingest_scan(
    session: Session, data: bytes, filename: str, tool: str, *, engagement_id: str
) -> Scan:
    parser = get_parser(tool)
    result = parser(data)
    now = datetime.now(UTC)

    scan = Scan(
        engagement_id=engagement_id,
        filename=filename,
        tool=tool,
        source_format=tool,
        imported_at=now,
        host_count=len(result),
    )
    session.add(scan)
    session.flush()
    assert scan.id is not None

    # Retain the raw bytes so a scan can be re-parsed or audited later. Strip any
    # directory components from the client-supplied filename before joining a path.
    scans_dir = engagement_scans_dir(engagement_id)
    scans_dir.mkdir(parents=True, exist_ok=True)
    raw_dest = scans_dir / f"{scan.id}_{Path(filename).name}"
    raw_dest.write_bytes(data)
    scan.raw_path = str(raw_dest.relative_to(DATA_DIR))

    for hr in result:
        _store_host(session, scan.id, hr, now, engagement_id=engagement_id)

    session.commit()
    session.refresh(scan)
    return scan
