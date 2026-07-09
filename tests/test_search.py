from __future__ import annotations

from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import (
    Annotation,
    Credential,
    CredentialHost,
    Host,
    Status,
    TargetType,
)
from penrecon.queries import search


def _scan(ip: str, hostname: str, service: str) -> bytes:
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{hostname}"/></hostnames>'
        f'<ports><port protocol="tcp" portid="5432"><state state="open"/>'
        f'<service name="{service}" product="db" version="14"/>'
        f"</port></ports></host></nmaprun>"
    ).encode()


def _host_id(session: Session, ip: str) -> int:
    host = session.exec(select(Host).where(Host.ip == ip)).one()
    assert host.id is not None
    return host.id


def _seed(session: Session) -> int:
    ingest_scan(session, _scan("10.0.0.5", "db.corp.local", "postgresql"), "a.xml", "nmap")
    hid = _host_id(session, "10.0.0.5")
    session.add(
        Annotation(
            target_type=TargetType.host,
            target_id=hid,
            body_md="weak postgres creds; pivot candidate",
            status=Status.interesting,
            tags=["pivot"],
        )
    )
    cred = Credential(kind="password", username="postgres", notes="reused on corp hosts")
    session.add(cred)
    session.flush()
    assert cred.id is not None
    session.add(CredentialHost(credential_id=cred.id, host_id=hid))
    session.commit()
    return hid


def test_empty_query_returns_nothing(session: Session) -> None:
    _seed(session)
    r = search(session, "   ")
    assert r.total == 0


def test_matches_across_all_three_sources(session: Session) -> None:
    _seed(session)
    r = search(session, "postgres")  # service name, note body, credential username
    assert len(r.hosts) == 1
    assert len(r.notes) == 1
    assert len(r.credentials) == 1
    assert r.total == 3


def test_hostname_and_note_tag_and_cred_notes(session: Session) -> None:
    _seed(session)
    assert len(search(session, "corp").hosts) == 1  # hostname db.corp.local
    assert len(search(session, "corp").credentials) == 1  # "reused on corp hosts"
    tag_hit = search(session, "pivot")  # matches the note by tag only, not the body word
    assert len(tag_hit.notes) == 1 and not tag_hit.hosts


def test_note_hit_links_back_to_host(session: Session) -> None:
    hid = _seed(session)
    note = search(session, "pivot").notes[0]
    assert note.href == f"/hosts/{hid}"
    assert note.kind == "host"
    assert "10.0.0.5" in note.where


def test_note_whose_target_is_gone_is_skipped(session: Session) -> None:
    _seed(session)
    # a service note pointing at a service id that never existed must not crash search
    session.add(
        Annotation(target_type=TargetType.service, target_id=99999, body_md="postgres ghost")
    )
    session.commit()
    assert len(search(session, "postgres").notes) == 1  # only the real host note survives
