from __future__ import annotations

from datetime import UTC, datetime

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session

from penrecon.ingest import ingest_scan
from penrecon.inventory import hide_hostname, link_hostname
from penrecon.queries import host_hostnames, host_rows


def _scan(ip: str, hostnames: list[str]) -> bytes:
    hn = "".join(f'<hostname name="{h}" type="user"/>' for h in hostnames)
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/><hostnames>{hn}</hostnames>'
        f'<ports><port protocol="tcp" portid="22"><state state="open"/>'
        f'<service name="ssh" method="probed"/></port></ports></host></nmaprun>'
    ).encode()


def test_multiple_hostnames_accumulate_and_dedup(session: Session) -> None:
    # scan A: one hostname; scan B: a second (plus the first again)
    ingest_scan(session, _scan("10.0.0.1", ["a.example"]), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    ingest_scan(session, _scan("10.0.0.1", ["b.example", "a.example"]), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    # re-ingest A again to prove dedup on repeat
    ingest_scan(session, _scan("10.0.0.1", ["a.example"]), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)

    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    names = host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [name for _, name in names] == ["a.example", "b.example"]


def test_hidden_hostname_stays_hidden_after_scan_and_manual_rediscovery(session: Session) -> None:
    ingest_scan(
        session, _scan("10.0.0.2", ["Keep.Example."]), "first.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    hostname_id, name = host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[0]
    assert name == "keep.example"
    assert hide_hostname(session, host.id, hostname_id, engagement_id=TEST_ENGAGEMENT_ID)
    session.commit()
    assert not hide_hostname(session, host.id, hostname_id, engagement_id=TEST_ENGAGEMENT_ID)
    assert host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == []

    ingest_scan(
        session, _scan("10.0.0.2", ["KEEP.EXAMPLE", "visible.example"]), "again.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    link_hostname(
        session, host.id, " Keep.Example. ", datetime.now(UTC),
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    session.commit()
    assert [name for _, name in host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)] == [
        "visible.example",
    ]


def test_scan_and_manual_hostname_spellings_share_one_visible_identity(session: Session) -> None:
    ingest_scan(
        session, _scan("10.0.0.3", ["WWW.Example."]), "scan.xml", "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    link_hostname(
        session, host.id, " www.EXAMPLE ", datetime.now(UTC),
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    session.commit()
    assert [name for _, name in host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)] == [
        "www.example",
    ]


def test_legacy_hostname_equivalence_preserves_hidden_link_and_existing_records(session: Session) -> None:
    from sqlmodel import select
    from penrecon.models import Host, Hostname, HostHostname

    host = Host(ip="10.0.0.50", engagement_id=TEST_ENGAGEMENT_ID)
    other = Host(ip="10.0.0.51", engagement_id=TEST_ENGAGEMENT_ID)
    legacy = Hostname(name="Legacy.Example.", engagement_id=TEST_ENGAGEMENT_ID)
    canonical = Hostname(name="legacy.example", engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([host, other, legacy, canonical])
    session.flush()
    assert host.id is not None and other.id is not None and legacy.id is not None and canonical.id is not None
    session.add_all([
        HostHostname(host_id=host.id, hostname_id=legacy.id, hidden=True, engagement_id=TEST_ENGAGEMENT_ID),
        HostHostname(host_id=host.id, hostname_id=canonical.id, hidden=False, engagement_id=TEST_ENGAGEMENT_ID),
        HostHostname(host_id=other.id, hostname_id=canonical.id, hidden=False, engagement_id=TEST_ENGAGEMENT_ID),
    ])
    session.commit()
    ingest_scan(session, _scan(host.ip, ["LEGACY.EXAMPLE"]), "rescan.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    link_hostname(session, host.id, " legacy.example. ", datetime.now(UTC), engagement_id=TEST_ENGAGEMENT_ID)
    session.commit()
    assert host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == []
    assert host_hostnames(session, other.id, engagement_id=TEST_ENGAGEMENT_ID) == [(canonical.id, "legacy.example")]
    assert [(name.id, name.name) for name in session.exec(select(Hostname).order_by(Hostname.id)).all()] == [
        (legacy.id, "Legacy.Example."), (canonical.id, "legacy.example"),
    ]
    assert len(session.exec(select(HostHostname)).all()) == 3


def test_legacy_visible_hostname_reuses_original_primary_identity(session: Session) -> None:
    from penrecon.models import Host, Hostname, HostHostname

    host = Host(ip="10.0.0.52", engagement_id=TEST_ENGAGEMENT_ID)
    original = Hostname(name="Keep.Example.", engagement_id=TEST_ENGAGEMENT_ID)
    collision = Hostname(name="keep.example", engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([host, original, collision])
    session.flush()
    assert host.id is not None and original.id is not None
    session.add(HostHostname(host_id=host.id, hostname_id=original.id, engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()
    ingest_scan(session, _scan(host.ip, ["keep.example"]), "again.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == [(original.id, "Keep.Example.")]
    assert hide_hostname(session, host.id, original.id, engagement_id=TEST_ENGAGEMENT_ID)
    session.commit()
    link_hostname(session, host.id, "KEEP.EXAMPLE.", datetime.now(UTC), engagement_id=TEST_ENGAGEMENT_ID)
    session.commit()
    assert host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == []


def test_many_discoveries_share_staged_hostname_identity_and_preserve_hidden_links(session: Session) -> None:
    from penrecon.models import Host, Hostname, HostHostname

    original_host = Host(ip="10.0.0.70", engagement_id=TEST_ENGAGEMENT_ID)
    legacy_name = Hostname(name="Shared.Example.", engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([original_host, legacy_name])
    session.flush()
    assert original_host.id is not None and legacy_name.id is not None
    session.add(HostHostname(host_id=original_host.id, hostname_id=legacy_name.id, hidden=True, engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()
    hosts = "".join(
        _scan(f"10.0.0.{number}", ["SHARED.EXAMPLE", "new.example"]).decode()
        .split("<nmaprun>", 1)[1].rsplit("</nmaprun>", 1)[0]
        for number in range(70, 90)
    )
    data = f"<nmaprun>{hosts}</nmaprun>".encode()
    for filename in ("first.xml", "again.xml"):
        ingest_scan(session, data, filename, "nmap", engagement_id=TEST_ENGAGEMENT_ID)
        rows = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
        assert len(rows) == 20
        assert host_hostnames(session, original_host.id, engagement_id=TEST_ENGAGEMENT_ID)[0][1] == "new.example"
        shared_ids = set()
        new_ids = set()
        for row in rows:
            names = host_hostnames(session, row.id, engagement_id=TEST_ENGAGEMENT_ID)
            assert [name for _, name in names] == (
                ["new.example"] if row.id == original_host.id else ["Shared.Example.", "new.example"]
            )
            for identity, name in names:
                (new_ids if name == "new.example" else shared_ids).add(identity)
        assert shared_ids == {legacy_name.id}
        assert len(new_ids) == 1
