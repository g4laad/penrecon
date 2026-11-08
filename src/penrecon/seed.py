"""Populate one empty engagement with linked, explicitly synthetic recon data."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

from sqlalchemy import func, select
from sqlmodel import Session, SQLModel

from penrecon.db import DATA_DIR, engagement_attachments_dir, engagement_scans_dir
from penrecon.models import (
    Annotation,
    Credential,
    CredentialHost,
    CredentialService,
    CredKind,
    Engagement,
    Host,
    HostHostname,
    HostScanEvidence,
    Hostname,
    Note,
    Observation,
    ObsState,
    OperationLog,
    Scan,
    ScanEvidenceComplete,
    Service,
    Status,
)
from penrecon.parsers import PortResult, get_parser

_PROFILES = (
    (22, "tcp", "ssh", "OpenSSH", "9.6"),
    (80, "tcp", "http", "nginx", "1.24.0"),
    (443, "tcp", "https", "Apache httpd", "2.4.58"),
    (5432, "tcp", "postgresql", "PostgreSQL", "16.2"),
    (53, "udp", "domain", "ISC BIND", "9.18"),
)


def _retain_mock_scan(
    session: Session, scan: Scan, host: Host, name: str,
    ports: list[PortResult], observed: datetime, created_files: list[Path],
) -> None:
    """Retain matching XML and durable evidence without committing seed work."""
    assert scan.id is not None and host.id is not None
    coverage = "".join(
        f'<scaninfo type="{"udp" if proto == "udp" else "syn"}" protocol="{proto}" '
        f'numservices="{len(numbers)}" services="{",".join(map(str, numbers))}"/>'
        for proto in sorted({port.proto for port in ports})
        if (numbers := sorted(port.port for port in ports if port.proto == proto))
    )
    port_xml = "".join(
        f'<port protocol="{port.proto}" portid="{port.port}">'
        f'<state state="{port.state}"/><service name="{port.service_name}" '
        f'product="{port.product}" version="{port.version}"/></port>'
        for port in ports
    )
    timestamp = int(observed.timestamp())
    xml = (
        f'<?xml version="1.0"?><nmaprun scanner="nmap" start="{timestamp}" version="7.95">'
        f'{coverage}<host><status state="up"/><address addr="{host.ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{name}" type="user"/></hostnames>'
        f'<ports>{port_xml}</ports></host>'
        f'<runstats><finished time="{timestamp}" elapsed="0" exit="success"/>'
        '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
    )
    evidence = get_parser("nmap")(xml.encode())[0]
    raw_path = engagement_scans_dir(scan.engagement_id) / f"{scan.id}_{scan.filename}"
    with raw_path.open("x") as raw_file:
        created_files.append(raw_path)
        raw_file.write(xml)
    scan.raw_path = str(raw_path.relative_to(DATA_DIR))
    session.add(HostScanEvidence(
        engagement_id=scan.engagement_id, scan_id=scan.id, host_id=host.id,
        scanned_at=evidence.scanned_at, coverage=evidence.coverage,
        ports=[asdict(port) for port in evidence.ports],
    ))
    session.add(ScanEvidenceComplete(
        engagement_id=scan.engagement_id, scan_id=scan.id,
    ))


def _seed_host_timeline(
    session: Session, host: Host, name: str, observed: datetime,
    created_files: list[Path],
) -> None:
    """Give the first host a navigable history ending at its normal snapshot."""
    http = PortResult(80, "tcp", service_name="http", product="nginx", version="1.22.1")
    https = PortResult(443, "tcp", service_name="https", product="Apache httpd", version="2.4.58")
    ssh = PortResult(22, "tcp", service_name="ssh", product="OpenSSH", version="9.6")
    closed = [replace(http, state="closed"), https]
    reopened = [replace(http, version="1.23.0"), replace(https, state="filtered"), ssh]
    snapshots = [
        ("baseline", [http, https]),
        ("partial-443-only", [https]),
        ("http-closed", closed),
        ("unchanged-closed", closed),
        ("http-reopened-https-filtered", reopened),
        ("no-ports-reported", []),
        *[(f"unchanged-{number:02d}", reopened) for number in range(1, 22)],
    ]
    assert host.id is not None
    host.first_seen = observed - timedelta(days=len(snapshots))
    for index, (label, ports) in enumerate(snapshots):
        scanned_at = observed - timedelta(days=len(snapshots) - index)
        scan = Scan(
            engagement_id=host.engagement_id, filename=f"mock-timeline-{index + 1:02d}-{label}.xml",
            tool="nmap", source_format="nmap", imported_at=scanned_at, host_count=1,
        )
        session.add(scan)
        session.flush()
        _retain_mock_scan(session, scan, host, name, ports, scanned_at, created_files)
        for port in ports:
            session.add(Observation(
                engagement_id=host.engagement_id, scan_id=scan.id, host_id=host.id,
                port=port.port, proto=port.proto, state=ObsState(port.state),
                service_name=port.service_name, product=port.product, version=port.version,
                extra={"mock": True}, observed_at=scanned_at,
            ))


@dataclass(frozen=True)
class SeededEngagement:
    """Committed result of creating one new synthetic workspace."""

    engagement_id: str
    name: str
    counts: dict[str, int]


def seed_mock_engagement(
    session: Session, count: int = 100, *, name: str,
) -> SeededEngagement:
    """Create and seed a new engagement, committing it only with its contents.

    This is the CLI's per-engagement command: a failed attempt rolls back the
    new engagement as well as its rows. ``seed_database`` compensates retained
    files on failure; previously completed engagements are never undone.
    """
    if not 100 <= count <= 131070:
        raise ValueError("count must be between 100 and 131070")
    engagement = Engagement(
        name=name, description="Synthetic recon workspace for local testing only.",
    )
    session.add(engagement)
    try:
        session.flush()
        engagement_id, engagement_name = engagement.id, engagement.name
        counts = seed_database(session, count, engagement_id=engagement_id)
    except Exception as failure:
        try:
            session.rollback()
        except Exception as rollback:
            failure.add_note(f"Seed engagement rollback failed: {rollback}")
        raise
    return SeededEngagement(engagement_id, engagement_name, counts)


def seed_database(
    session: Session, count: int = 100, *, engagement_id: str
) -> dict[str, int]:
    """Seed only an existing, empty engagement after local DB initialization.

    Count, engagement existence, and emptiness are checked before creating files
    or rows. All addresses are in the benchmark-only 198.18.0.0/15 range and names
    use .test. No network requests or commands are executed. Rows commit together;
    failed writes roll back rows and remove only files created by this attempt.
    """
    if not 100 <= count <= 131070:
        raise ValueError("count must be between 100 and 131070")
    if session.get(Engagement, engagement_id) is None:
        raise ValueError("engagement not found")
    tables = [
        table for table in SQLModel.metadata.sorted_tables if "engagement_id" in table.c
    ]
    for table in tables:
        if session.execute(
            select(table).where(table.c.engagement_id == engagement_id).limit(1)
        ).first() is not None:
            raise ValueError("mock data requires an empty engagement")

    now = datetime.now(UTC)
    statuses = tuple(Status)
    kinds = tuple(CredKind)
    states = tuple(ObsState)
    created_files: list[Path] = []
    scans_dir = engagement_scans_dir(engagement_id)
    attachments_dir = engagement_attachments_dir(engagement_id)
    scans_dir.mkdir(parents=True, exist_ok=True)
    attachments_dir.mkdir(parents=True, exist_ok=True)
    try:
        for index in range(count):
            number = index + 1
            ip = str(IPv4Address(int(IPv4Address("198.18.0.0")) + number))
            name = f"host-{number:05d}.mock.test"
            port, proto, service_name, product, version = _PROFILES[index % len(_PROFILES)]
            state = states[index % len(states)]
            observed = now - timedelta(minutes=count - index)
            host = Host(engagement_id=engagement_id, ip=ip, first_seen=observed, last_seen=observed)
            hostname = Hostname(engagement_id=engagement_id, name=name)
            scan = Scan(
                engagement_id=engagement_id,
                filename=f"mock-{number:05d}.xml", tool="nmap", source_format="nmap",
                imported_at=observed, host_count=1,
            )
            credential = Credential(
                engagement_id=engagement_id,
                kind=kinds[index % len(kinds)], username=f"mock-user-{number:05d}",
                secret=f"MOCK-NOT-A-REAL-SECRET-{number:05d}",
                notes="Synthetic credential for local testing only.", created_at=observed,
            )
            session.add_all([host, hostname, scan, credential])
            session.flush()
            assert host.id is not None and hostname.id is not None
            assert scan.id is not None and credential.id is not None
            profiles = _PROFILES if index == 0 else (_PROFILES[index % len(_PROFILES)],)
            ports: list[PortResult] = []
            for svc_port, svc_proto, svc_name, svc_product, svc_version in profiles:
                svc_state = ObsState.open if index == 0 else state
                service = Service(
                    engagement_id=engagement_id, host_id=host.id, port=svc_port, proto=svc_proto
                )
                session.add(service)
                session.flush()
                assert service.id is not None
                session.add_all([
                    Observation(
                        engagement_id=engagement_id,
                        scan_id=scan.id, host_id=host.id, port=svc_port, proto=svc_proto,
                        state=svc_state, service_name=svc_name, product=svc_product,
                        version=svc_version, extra={"mock": True}, observed_at=observed,
                    ),
                    Annotation(
                        engagement_id=engagement_id,
                        service_id=service.id, status=statuses[(index + 1) % len(statuses)],
                        tags=["mock", svc_name], updated_at=observed,
                    ),
                    CredentialService(
                        engagement_id=engagement_id, credential_id=credential.id, service_id=service.id
                    ),
                ])
                ports.append(PortResult(
                    svc_port, svc_proto, state=svc_state.value,
                    service_name=svc_name, product=svc_product, version=svc_version,
                ))

            _retain_mock_scan(session, scan, host, name, ports, observed, created_files)
            if index == 0:
                _seed_host_timeline(session, host, name, observed, created_files)

            attachment = attachments_dir / f"mock-{number:05d}.txt"
            output = f"MOCK OUTPUT ONLY: {ip}:{port}/{proto} {state.value} {product} {version}\n"
            with attachment.open("x") as attachment_file:
                created_files.append(attachment)
                attachment_file.write(output)
            session.add_all([
                HostHostname(
                    engagement_id=engagement_id, host_id=host.id,
                    hostname_id=hostname.id, last_seen=observed,
                ),
                Annotation(
                    engagement_id=engagement_id,
                    host_id=host.id, status=statuses[index % len(statuses)],
                    tags=["mock", "internal"], updated_at=observed,
                ),
                Note(
                    engagement_id=engagement_id,
                    host_id=host.id, title=f"Mock triage: {name}",
                    body_md=f"## Synthetic finding\n\nReview `{ip}:{port}` ({product}).\n\n"
                    "- [x] Discovery complete\n- [ ] Validate configuration\n\n"
                    "This is generated test data, not a real finding.",
                    created_at=observed, updated_at=observed,
                ),
                CredentialHost(
                    engagement_id=engagement_id, credential_id=credential.id, host_id=host.id
                ),
                OperationLog(
                    engagement_id=engagement_id,
                    started_at=observed, ended_at=observed + timedelta(seconds=30),
                    source="198.19.255.254", destination=ip, tool="nmap",
                    user_context=f"mock-operator-{index % 5 + 1}",
                    command=f"nmap -sV -p {port} {ip}", output=output,
                    description=f"Mock reconnaissance of {name}",
                    comments="Synthetic operation; this command was not executed.",
                    tags=["mock", "recon"], attachment_name=attachment.name,
                    attachment_path=str(attachment.relative_to(DATA_DIR)),
                    attachment_media_type="text/plain",
                    created_at=observed, updated_at=observed,
                ),
            ])
        session.flush()
        counts = {
            table.name: session.execute(
                select(func.count()).select_from(table)
                .where(table.c.engagement_id == engagement_id)
            ).scalar_one()
            for table in tables
        }
        session.commit()
    except Exception as failure:
        try:
            session.rollback()
        except Exception as rollback:
            failure.add_note(f"Seed rollback failed: {rollback}")
        for path in created_files:
            try:
                path.unlink(missing_ok=True)
            except OSError as cleanup:
                failure.add_note(f"Seed file cleanup pending at {path}: {cleanup}")
        raise

    return counts
