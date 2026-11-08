"""Import command shared by web uploads and the CLI.

Parse before mutation, stage immutable evidence, retain the original bytes, then
commit. Pre-commit failures roll back inventory and remove uncommitted raw files.
Post-commit refresh is outside rollback: committed evidence must remain retained.
Annotations and manual overrides are never touched.
"""

from __future__ import annotations

from datetime import UTC, datetime
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from sqlmodel import Session, select

from penrecon.db import DATA_DIR, engagement_scans_dir
from penrecon.inventory import DiscoveryIndex, link_hostname, normalize_ip
from penrecon.models import (
    Host,
    HostScanEvidence,
    Observation,
    ObsState,
    Scan,
    ScanEvidenceComplete,
    Service,
)
from penrecon.parsers import HostResult, ScanResult, get_parser


class ScanParseError(ValueError):
    """Scan content does not match the selected tool's import format."""



def _upsert_host(
    session: Session, ip: str, now: datetime, discovery: DiscoveryIndex, *, engagement_id: str
) -> Host:
    ip = normalize_ip(ip)
    host = discovery.hosts.get(ip)
    if host is None:
        host = Host(engagement_id=engagement_id, ip=ip, first_seen=now, last_seen=now)
        session.add(host)
        session.flush()
        discovery.hosts[ip] = host
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
    session: Session, scan_id: int, hr: HostResult, now: datetime,
    discovery: DiscoveryIndex, *, engagement_id: str
) -> None:
    host = _upsert_host(session, hr.ip, now, discovery, engagement_id=engagement_id)
    assert host.id is not None
    session.add(HostScanEvidence(
        engagement_id=engagement_id,
        scan_id=scan_id,
        host_id=host.id,
        scanned_at=hr.scanned_at,
        coverage=hr.coverage,
        ports=[asdict(port) for port in hr.ports],
    ))
    for name in hr.hostnames:
        if name:
            link_hostname(session, host.id, name, now, engagement_id=engagement_id, discovery=discovery)
    for p in hr.ports:
        _upsert_service(session, host.id, p.port, p.proto, engagement_id=engagement_id)
        session.add(
            Observation(
                engagement_id=engagement_id,
                scan_id=scan_id,
                host_id=host.id,
                port=p.port,
                proto=p.proto,
                state=ObsState(p.state),
                service_name=p.service_name,
                product=p.product,
                version=p.version,
                extra=p.extra,
                observed_at=hr.scanned_at or now,
            )
        )


def _parse_scan(data: bytes, tool: str) -> ScanResult:
    try:
        return get_parser(tool)(data)
    except (ValueError, LookupError) as exc:
        guidance = (
            "Choose an nmap XML file exported with -oX, then upload again."
            if tool == "nmap"
            else "Correct the file or select the matching tool format, then upload again."
        )
        raise ScanParseError(f"{exc}. {guidance}") from exc


def _stage_scan(
    session: Session, result: ScanResult, filename: str, tool: str,
    now: datetime, *, engagement_id: str,
) -> Scan:
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
    discovery = DiscoveryIndex.load(session, engagement_id=engagement_id)
    for host in result:
        _store_host(session, scan.id, host, now, discovery, engagement_id=engagement_id)
    session.add(ScanEvidenceComplete(engagement_id=engagement_id, scan_id=scan.id))
    session.flush()
    return scan


def _retain_raw(scan: Scan, data: bytes, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    scan.raw_path = str(destination.relative_to(DATA_DIR))


def _rollback_import(
    session: Session, destination: Path | None, error: BaseException,
) -> None:
    try:
        session.rollback()
    except Exception as exc:
        error.add_note(f"Scan import rollback failed: {exc}")
    if destination is not None:
        try:
            destination.unlink(missing_ok=True)
        except Exception as exc:
            error.add_note(f"Uncommitted raw scan cleanup failed at {destination}: {exc}")


def ingest_scan(
    session: Session, data: bytes, filename: str, tool: str, *, engagement_id: str
) -> Scan:
    """Commit one scan, retaining raw bytes only for committed evidence.

    Parsing errors leave the session untouched. Persistence failures roll back
    the command; any cleanup failure is attached to, never replaces, that error.
    """
    result = _parse_scan(data, tool)
    destination: Path | None = None
    try:
        scan = _stage_scan(
            session, result, filename, tool, datetime.now(UTC), engagement_id=engagement_id,
        )
        # Assign before writing so even a partially written file is cleaned up.
        # Only the basename of a client-supplied filename enters the retained path.
        destination = engagement_scans_dir(engagement_id) / f"{scan.id}_{uuid4().hex}_{Path(filename).name}"
        _retain_raw(scan, data, destination)
        session.commit()
    except BaseException as exc:
        _rollback_import(session, destination, exc)
        raise
    session.refresh(scan)
    return scan
