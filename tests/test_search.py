from __future__ import annotations

from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import (
    Annotation,
    Credential,
    CredentialHost,
    Host,
    Note,
    Status,
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
            host_id=hid,
            status=Status.interesting,
            tags=["pivot"],  # triage tag — findable via host search
        )
    )
    session.add(
        Note(
            host_id=hid,
            title="Postgres",
            body_md="weak postgres creds; reuse candidate",
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


def test_hostname_and_tag_and_cred_notes(session: Session) -> None:
    _seed(session)
    assert len(search(session, "corp").hosts) == 1  # hostname db.corp.local
    assert len(search(session, "corp").credentials) == 1  # "reused on corp hosts"
    tag_hit = search(session, "pivot")  # a triage tag surfaces its host, not a note
    assert len(tag_hit.hosts) == 1 and not tag_hit.notes


def test_note_hit_links_back_to_host(session: Session) -> None:
    hid = _seed(session)
    note = search(session, "candidate").notes[0]  # matched on note body
    assert note.href == f"/hosts/{hid}"
    assert note.kind == "host"
    assert note.title == "Postgres"
    assert "10.0.0.5" in note.where


def test_deleting_host_cascades_its_note_out_of_search(session: Session) -> None:
    hid = _seed(session)
    assert len(search(session, "postgres").notes) == 1
    host = session.get(Host, hid)
    assert host is not None
    session.delete(host)  # FK ON DELETE CASCADE drops the note with the host
    session.commit()
    assert search(session, "postgres").notes == []
