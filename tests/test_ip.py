from __future__ import annotations

from pathlib import Path
import pytest
from sqlmodel import Session

from penrecon.inventory import normalize_ip
from penrecon.ingest import ingest_scan
from penrecon.queries import host_hostnames, host_rows, resolved_services
from tests.fixtures import TEST_ENGAGEMENT_ID


def test_normalize_ip_accepts_and_canonicalizes() -> None:
    assert normalize_ip("10.0.0.5") == "10.0.0.5"
    assert normalize_ip("  192.168.1.1  ") == "192.168.1.1"
    assert normalize_ip("2001:0DB8::0001") == "2001:db8::1"
    assert normalize_ip("::1") == "::1"


def test_normalize_ip_rejects_non_ip() -> None:
    for bad in ["", "not-an-ip", "10.0.0.256", "10.0.0", "1.2.3.4.5",
                "10.0.0.01", "gw.internal", "1234::xyz"]:
        with pytest.raises(ValueError):
            normalize_ip(bad)


def test_scan_formats_share_canonical_inventory_identities(session: Session) -> None:
    nmap = b"""<nmaprun><host>
      <address addr="2001:0DB8::0001" addrtype="ipv6"/>
      <hostnames><hostname name=" API.Example. "/></hostnames>
      <ports><port protocol=" TCP " portid="443"><state state="open"/></port></ports>
    </host></nmaprun>"""
    ingest_scan(session, nmap, "first.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(
        session, b"api.example. 2001:db8::1\nAPI.EXAMPLE 2001:0db8:0:0:0:0:0:1",
        "names.txt", "amass", engagement_id=TEST_ENGAGEMENT_ID,
    )
    ingest_scan(
        session, nmap.replace(b"2001:0DB8::0001", b"2001:db8::1").replace(b" TCP ", b"tcp"),
        "second.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID,
    )
    rows = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
    assert len(rows) == 1
    assert rows[0].ip == "2001:db8::1"
    assert rows[0].hostnames == ["api.example"]
    assert [name for _, name in host_hostnames(
        session, rows[0].id, engagement_id=TEST_ENGAGEMENT_ID,
    )] == ["api.example"]
    services = resolved_services(session, rows[0].id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [(service.port, service.proto) for service in services] == [(443, "tcp")]


@pytest.mark.parametrize("collision", [False, True])
def test_import_reuses_legacy_ip_identity_without_merging_existing_collisions(
    session: Session, collision: bool,
) -> None:
    from penrecon.models import Host, Note
    from penrecon.queries import notes_for

    legacy = Host(ip="2001:0DB8:0:0:0:0:0:1", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(legacy)
    session.flush()
    assert legacy.id is not None
    session.add(Note(host_id=legacy.id, title="Legacy notes", body_md="retain me", engagement_id=TEST_ENGAGEMENT_ID))
    newer = Host(ip="2001:db8::1", engagement_id=TEST_ENGAGEMENT_ID) if collision else None
    if newer is not None:
        session.add(newer)
        session.flush()
        assert newer.id is not None
        session.add(Note(host_id=newer.id, title="Separate notes", body_md="also retain", engagement_id=TEST_ENGAGEMENT_ID))
    # Old malformed values must not prevent matching another valid identity.
    session.add(Host(ip="old-invalid-address", engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()
    data = b'<nmaprun><host><address addr="2001:db8::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'
    ingest_scan(session, data, "new.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    rows = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
    assert len(rows) == (3 if collision else 2)
    assert next(row for row in rows if row.id == legacy.id).ip == "2001:0DB8:0:0:0:0:0:1"
    assert [service.port for service in resolved_services(session, legacy.id, engagement_id=TEST_ENGAGEMENT_ID)] == [443]
    assert notes_for(session, legacy.id, engagement_id=TEST_ENGAGEMENT_ID)[0].body_md == "retain me"
    if newer is not None:
        assert newer.id is not None
        assert resolved_services(session, newer.id, engagement_id=TEST_ENGAGEMENT_ID) == []
        from penrecon.queries import latest_observations
        assert latest_observations(session, newer.id, engagement_id=TEST_ENGAGEMENT_ID) == {}
        assert notes_for(session, newer.id, engagement_id=TEST_ENGAGEMENT_ID)[0].body_md == "also retain"


def test_legacy_raw_history_matches_equivalent_ip_spelling(session: Session, tmp_path: Path) -> None:
    from penrecon.models import Host, Scan
    from penrecon.queries import latest_observations

    host = Host(ip="2001:0DB8::0001", engagement_id=TEST_ENGAGEMENT_ID)
    raw = tmp_path / "legacy.xml"
    raw.write_bytes(b'<nmaprun><host><address addr="2001:db8:0:0:0:0:0:1" addrtype="ipv6"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>')
    session.add(host)
    session.add(Scan(filename="legacy.xml", tool="nmap", source_format="nmap", raw_path=str(raw), engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()
    assert host.id is not None
    observed = latest_observations(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert observed[(443, "tcp")].state == "open"
