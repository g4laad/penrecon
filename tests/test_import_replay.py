from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import event
from sqlmodel import Session, select

from penrecon.history import ReplayInputs, host_history, rebuild_history
from penrecon.ingest import ingest_scan
from penrecon.models import (
    Engagement,
    Host,
    HostScanEvidence,
    Observation,
    ObsState,
    Scan,
    ScanEvidenceComplete,
    Service,
)
from penrecon.queries.inventory import host_rows, resolved_services
from tests.fixtures import TEST_ENGAGEMENT_ID


def _scan(ip: str, timestamp: int = 100, ports: str | None = None, scaninfo: str = "") -> bytes:
    if ports is None:
        ports = (
            '<port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http" product="nginx" version="1.0"/></port>'
        )
    return (
        f'<nmaprun start="{timestamp}">{scaninfo}<host><status state="up"/>'
        f'<address addr="{ip}" addrtype="{"ipv6" if ":" in ip else "ipv4"}"/><ports>{ports}</ports>'
        '</host></nmaprun>'
    ).encode()


def _host(session: Session, ip: str, engagement_id: str = TEST_ENGAGEMENT_ID) -> Host:
    return session.exec(select(Host).where(
        Host.engagement_id == engagement_id, Host.ip == ip,
    )).one()


def test_complete_scan_does_not_restore_raw_evidence_to_recreated_host(session: Session) -> None:
    ingest_scan(
        session, _scan("10.0.0.2"), "original.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    session.delete(_host(session, "10.0.0.2"))
    session.commit()
    replacement = Host(engagement_id=TEST_ENGAGEMENT_ID, ip="10.0.0.2")
    session.add(replacement)
    session.flush()
    assert replacement.id is not None
    session.add(Service(
        engagement_id=TEST_ENGAGEMENT_ID, host_id=replacement.id, port=80, proto="tcp",
    ))
    session.commit()

    entries, latest = host_history(session, replacement.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert entries == []
    assert latest == {}
    assert [(view.state, view.version) for view in resolved_services(
        session, replacement.id, engagement_id=TEST_ENGAGEMENT_ID,
    )] == [("unknown", None)]


def test_legacy_raw_recovers_history_without_materializing_evidence(
    session: Session, tmp_path: Path,
) -> None:
    data = _scan("2001:0DB8::0001")
    raw = tmp_path / "legacy.xml"
    raw.write_bytes(data)
    host = Host(engagement_id=TEST_ENGAGEMENT_ID, ip="2001:db8::1")
    scan = Scan(
        engagement_id=TEST_ENGAGEMENT_ID, filename="legacy.xml", tool="nmap",
        source_format="nmap", raw_path=str(raw),
    )
    session.add_all([host, scan])
    session.flush()
    assert host.id is not None
    session.add(Service(
        engagement_id=TEST_ENGAGEMENT_ID, host_id=host.id, port=80, proto="tcp",
    ))
    session.commit()

    entries, latest = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [entry.filename for entry in entries] == ["legacy.xml"]
    assert latest[(80, "tcp")].version == "1.0"
    assert [(view.state, view.version) for view in resolved_services(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID,
    )] == [("open", "1.0")]
    assert session.exec(select(HostScanEvidence)).all() == []
    assert session.exec(select(Observation)).all() == []
    assert session.exec(select(ScanEvidenceComplete)).all() == []
    assert raw.read_bytes() == data


def test_complete_scan_keeps_observation_fallback_without_raw_recovery(session: Session) -> None:
    scan = ingest_scan(
        session, b"<nmaprun/>", "empty.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    assert scan.id is not None
    host = Host(engagement_id=TEST_ENGAGEMENT_ID, ip="10.0.0.9")
    session.add(host)
    session.flush()
    assert host.id is not None
    session.add_all([
        Service(engagement_id=TEST_ENGAGEMENT_ID, host_id=host.id, port=22, proto="tcp"),
        Observation(
            engagement_id=TEST_ENGAGEMENT_ID, host_id=host.id, scan_id=scan.id,
            port=22, proto="tcp", state=ObsState.filtered, service_name="ssh",
            observed_at=datetime(2000, 1, 1, tzinfo=UTC),
        ),
    ])
    session.commit()

    entries, latest = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert len(entries) == 1
    assert entries[0].time_source == "import"
    assert latest[(22, "tcp")].state == "filtered"
    assert [(view.state, view.service_name) for view in resolved_services(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID,
    )] == [("filtered", "ssh")]


def test_scoped_out_of_order_and_zero_port_scans_preserve_current_state(session: Session) -> None:
    scope = TEST_ENGAGEMENT_ID
    other_scope = "other-replay-engagement"
    session.add(Engagement(id=other_scope, name="Other replay engagement"))
    session.commit()
    ingest_scan(
        session, _scan("10.0.0.8", 100), "baseline.xml", "nmap", engagement_id=scope,
    )
    covered = ingest_scan(
        session, _scan(
            "10.0.0.8", 300, '<extraports state="closed" count="2"/>',
            '<scaninfo protocol="tcp" services="22,80" numservices="2"/>',
        ), "covered.xml", "nmap", engagement_id=scope,
    )
    ingest_scan(
        session, _scan(
            "10.0.0.8", 200,
            '<port protocol="tcp" portid="443"><state state="open"/>'
            '<service name="https"/></port>',
        ), "partial.xml", "nmap", engagement_id=scope,
    )
    ingest_scan(
        session, _scan("10.0.0.8", 400, ""), "zero-port.xml", "nmap", engagement_id=scope,
    )
    ingest_scan(
        session, _scan("10.0.0.8", 500), "other.xml", "nmap", engagement_id=other_scope,
    )
    host = _host(session, "10.0.0.8")
    other = _host(session, "10.0.0.8", other_scope)
    assert host.id is not None and other.id is not None
    entries, latest = host_history(session, host.id, engagement_id=scope)
    assert [entry.filename for entry in entries] == [
        "baseline.xml", "partial.xml", "covered.xml", "zero-port.xml",
    ]
    assert latest[(80, "tcp")].scan_id == covered.id
    assert set(latest) == {(80, "tcp"), (443, "tcp")}
    assert entries[-1].changes == []
    assert {(identity.port, identity.proto) for identity in entries[-1].not_reported} == {
        (80, "tcp"), (443, "tcp"),
    }
    assert {(view.port, view.state, view.version) for view in resolved_services(
        session, host.id, engagement_id=scope,
    )} == {(80, "closed", "1.0"), (443, "open", None)}
    assert [(view.port, view.state) for view in resolved_services(
        session, other.id, engagement_id=other_scope,
    )] == [(80, "open")]
    assert host_history(session, other.id, engagement_id=scope) == ([], {})
    assert host_rows(session, engagement_id=scope)[0].open_count == 1
    inputs = ReplayInputs.load(session, engagement_id=scope, host_ids={host.id, other.id})
    replayed, current = rebuild_history(session, host.id, engagement_id=scope, inputs=inputs)
    assert [entry.filename for entry in replayed] == [
        "baseline.xml", "partial.xml", "covered.xml", "zero-port.xml",
    ]
    assert {(identity, str(row.state)) for identity, row in current.items()} == {
        ((80, "tcp"), "closed"), ((443, "tcp"), "open"),
    }
    assert rebuild_history(session, other.id, engagement_id=scope, inputs=inputs) == ([], {})


def test_selected_replay_respects_legacy_canonical_sibling_attribution(
    session: Session, tmp_path: Path,
) -> None:
    raw = tmp_path / "attributed.xml"
    raw.write_bytes(_scan("2001:db8::1"))
    owner = Host(engagement_id=TEST_ENGAGEMENT_ID, ip="2001:0DB8::0001")
    sibling = Host(engagement_id=TEST_ENGAGEMENT_ID, ip="2001:db8::1")
    scan = Scan(
        engagement_id=TEST_ENGAGEMENT_ID, filename="attributed.xml", tool="nmap",
        source_format="nmap", raw_path=str(raw),
    )
    session.add_all([owner, sibling, scan])
    session.flush()
    assert owner.id is not None and sibling.id is not None and scan.id is not None
    session.add_all([
        HostScanEvidence(
            engagement_id=TEST_ENGAGEMENT_ID, scan_id=scan.id, host_id=owner.id,
            ports=[{"port": 80, "proto": "tcp", "state": "open", "version": "owner"}],
        ),
        Service(engagement_id=TEST_ENGAGEMENT_ID, host_id=owner.id, port=80, proto="tcp"),
        Service(engagement_id=TEST_ENGAGEMENT_ID, host_id=sibling.id, port=80, proto="tcp"),
    ])
    session.commit()

    inputs = ReplayInputs.load(
        session, engagement_id=TEST_ENGAGEMENT_ID, host_ids={sibling.id},
    )
    assert rebuild_history(
        session, sibling.id, engagement_id=TEST_ENGAGEMENT_ID, inputs=inputs,
    ) == ([], {})
    assert host_history(session, sibling.id, engagement_id=TEST_ENGAGEMENT_ID) == ([], {})
    assert resolved_services(
        session, sibling.id, engagement_id=TEST_ENGAGEMENT_ID,
    )[0].state == "unknown"
    assert resolved_services(
        session, owner.id, engagement_id=TEST_ENGAGEMENT_ID,
    )[0].version == "owner"


def test_shared_replay_inputs_batch_sources_and_do_not_read_per_host(session: Session) -> None:
    for index in range(4):
        ingest_scan(
            session, _scan(f"10.0.0.{index + 1}"), f"host-{index}.xml", "nmap",
            engagement_id=TEST_ENGAGEMENT_ID,
        )
    host_ids = {
        host.id for host in session.exec(select(Host)).all() if host.id is not None
    }
    statements: list[str] = []

    def record(
        connection: Any, cursor: Any, statement: str, parameters: Any,
        context: Any, executemany: bool,
    ) -> None:
        statements.append(statement)

    bind = session.get_bind()
    event.listen(bind, "before_cursor_execute", record)
    try:
        inputs = ReplayInputs.load(session, engagement_id=TEST_ENGAGEMENT_ID)
        source_reads = len(statements)
        assert source_reads <= 6
        for host_id in host_ids:
            entries, latest = rebuild_history(
                session, host_id, engagement_id=TEST_ENGAGEMENT_ID, inputs=inputs,
            )
            assert len(entries) == 1
            assert latest[(80, "tcp")].version == "1.0"
        assert len(statements) == source_reads
    finally:
        event.remove(bind, "before_cursor_execute", record)
