"""Populate one empty engagement with linked, explicitly synthetic recon data."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

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
    Hostname,
    Note,
    Observation,
    ObsState,
    OperationLog,
    Scan,
    Service,
    Status,
)

_PROFILES = (
    (22, "tcp", "ssh", "OpenSSH", "9.6"),
    (80, "tcp", "http", "nginx", "1.24.0"),
    (443, "tcp", "https", "Apache httpd", "2.4.58"),
    (5432, "tcp", "postgresql", "PostgreSQL", "16.2"),
    (53, "udp", "domain", "ISC BIND", "9.18"),
)


def seed_database(
    session: Session, count: int = 100, *, engagement_id: str
) -> dict[str, int]:
    """Create at least ``count`` rows per domain table in an empty engagement.

    All addresses are in the benchmark-only 198.18.0.0/15 range and names use
    .test. No network requests or commands are executed. The caller initializes
    the database first. Rows commit together; failed writes remove generated files.
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
    created_files = []
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
            port_xml = []
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
                port_xml.append(
                    f'<port protocol="{svc_proto}" portid="{svc_port}">'
                    f'<state state="{svc_state.value}"/><service name="{svc_name}" '
                    f'product="{svc_product}" version="{svc_version}"/></port>'
                )

            raw_path = scans_dir / f"{scan.id}_{scan.filename}"
            xml = (
                '<?xml version="1.0"?><nmaprun scanner="nmap" start="0" version="7.95">'
                f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
                f'<hostnames><hostname name="{name}" type="user"/></hostnames>'
                '<ports>' + "".join(port_xml) + '</ports></host>'
                '<runstats><finished time="0" elapsed="0" exit="success"/>'
                '<hosts up="1" down="0" total="1"/></runstats></nmaprun>'
            )
            with raw_path.open("x") as raw_file:
                created_files.append(raw_path)
                raw_file.write(xml)
            scan.raw_path = str(raw_path.relative_to(DATA_DIR))

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
        session.commit()
    except Exception:
        session.rollback()
        for path in created_files:
            path.unlink(missing_ok=True)
        raise

    return {
        table.name: session.execute(
            select(func.count()).select_from(table)
            .where(table.c.engagement_id == engagement_id)
        ).scalar_one()
        for table in tables
    }
