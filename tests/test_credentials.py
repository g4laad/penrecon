from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlalchemy import event
from sqlmodel import Session
from sqlmodel import select

from penrecon.ingest import ingest_scan
from penrecon.queries import resolved_services
from tests.fixtures import SCAN_A

from penrecon.models import (
    CredKind,
    Credential,
    CredentialHost,
    CredentialService,
    Host,
    Service,
)
from penrecon.queries import credential_summaries, credential_view, credentials_for_host


def _host(session: Session, ip: str) -> Host:
    h = Host(ip=ip, engagement_id=TEST_ENGAGEMENT_ID)
    session.add(h)
    session.commit()
    session.refresh(h)
    return h


def _service(session: Session, host_id: int, port: int, name: str | None = None) -> Service:
    s = Service(host_id=host_id, port=port, proto="tcp", m_service_name=name, engagement_id=TEST_ENGAGEMENT_ID)
    session.add(s)
    session.commit()
    session.refresh(s)
    return s


def test_credential_view_lists_host_and_service_links(session: Session) -> None:
    h = _host(session, "10.0.0.1")
    svc = _service(session, h.id, 22, "ssh")  # type: ignore[arg-type]
    c = Credential(kind=CredKind.password, username="root", secret="toor", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(c)
    session.commit()
    session.refresh(c)
    session.add(CredentialHost(credential_id=c.id, host_id=h.id, engagement_id=TEST_ENGAGEMENT_ID))  # type: ignore[arg-type]
    session.add(CredentialService(credential_id=c.id, service_id=svc.id, engagement_id=TEST_ENGAGEMENT_ID))  # type: ignore[arg-type]
    session.commit()

    v = credential_view(session, c.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert v is not None
    assert (v.username, v.secret) == ("root", "toor")
    assert [x.ip for x in v.hosts] == ["10.0.0.1"]
    assert [(s.port, s.proto, s.name) for s in v.services] == [(22, "tcp", "ssh")]


def test_credentials_for_host_includes_service_only_links(session: Session) -> None:
    h = _host(session, "10.0.0.2")
    svc = _service(session, h.id, 445, "microsoft-ds")  # type: ignore[arg-type]
    c = Credential(kind=CredKind.hash, secret="aad3b435:31d6cfe0", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(c)
    session.commit()
    session.refresh(c)
    session.add(CredentialService(credential_id=c.id, service_id=svc.id, engagement_id=TEST_ENGAGEMENT_ID))  # type: ignore[arg-type]
    session.commit()

    # tied to the host only through its service, never linked to the host directly
    got = credentials_for_host(session, h.id, engagement_id=TEST_ENGAGEMENT_ID)  # type: ignore[arg-type]
    assert len(got) == 1 and got[0].secret == "aad3b435:31d6cfe0"

    other = _host(session, "10.0.0.3")
    assert credentials_for_host(session, other.id, engagement_id=TEST_ENGAGEMENT_ID) == []  # type: ignore[arg-type]


def test_pickable_services_scoped_to_linked_hosts(session: Session) -> None:
    h1 = _host(session, "10.0.0.10")
    s_pick = _service(session, h1.id, 22, "ssh")  # type: ignore[arg-type]
    s_linked = _service(session, h1.id, 80, "http")  # type: ignore[arg-type]
    h2 = _host(session, "10.0.0.11")
    _service(session, h2.id, 3389, "rdp")  # unlinked host — must not appear  # type: ignore[arg-type]

    c = Credential(kind=CredKind.password, username="root", secret="toor", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(c)
    session.commit()
    session.refresh(c)
    session.add(CredentialHost(credential_id=c.id, host_id=h1.id, engagement_id=TEST_ENGAGEMENT_ID))  # type: ignore[arg-type]
    session.add(CredentialService(credential_id=c.id, service_id=s_linked.id, engagement_id=TEST_ENGAGEMENT_ID))  # type: ignore[arg-type]
    session.commit()

    v = credential_view(session, c.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert v is not None
    # only h1's services, minus the already-linked one → just s_pick
    assert [s.service_id for s in v.pickable_services] == [s_pick.id]

    # a credential with no host linked can pick nothing
    c2 = Credential(kind=CredKind.password, username="x", secret="y", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(c2)
    session.commit()
    view = credential_view(session, c2.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert view is not None and view.pickable_services == []


def test_credential_service_names_follow_current_state(session: Session) -> None:
    ingest_scan(session, SCAN_A.encode(), "old.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    updated = SCAN_A.replace('name="ssh"', 'name="ssh-new"').replace('name="http"', 'name="http-new"')
    ingest_scan(session, updated.encode(), "new.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = session.exec(select(Host).where(Host.ip == "10.0.0.1")).one()
    services = {
        svc.port: svc for svc in session.exec(select(Service)).all()
    }
    credential = Credential(username="operator", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(credential)
    session.flush()
    assert credential.id is not None and host.id is not None and services[22].id is not None
    session.add(CredentialHost(
        credential_id=credential.id, host_id=host.id, engagement_id=TEST_ENGAGEMENT_ID,
    ))
    session.add(CredentialService(
        credential_id=credential.id, service_id=services[22].id, engagement_id=TEST_ENGAGEMENT_ID,
    ))
    session.commit()

    def names() -> tuple[str | None, str | None]:
        view = credential_view(session, credential.id, engagement_id=TEST_ENGAGEMENT_ID)
        assert view is not None
        return view.services[0].name, view.pickable_services[0].name

    assert names() == ("ssh-new", "http-new")
    services[22].m_service_name = "manual-ssh"
    services[80].m_service_name = "manual-http"
    session.commit()
    assert names() == ("manual-ssh", "manual-http")

    services[22].m_service_name = ""
    services[80].m_service_name = None
    session.commit()
    assert names() == ("ssh-new", "http-new")

    unnamed = SCAN_A.replace('name="ssh"', 'name=""').replace('name="http"', 'name=""')
    ingest_scan(session, unnamed.encode(), "unnamed.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert names() == (None, None)
    assert {svc.port: svc.service_name for svc in resolved_services(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID,
    )} == {22: None, 80: None}


def test_credential_summaries_preserve_full_notes_and_association_filters(session: Session) -> None:
    host = _host(session, "10.42.0.7")
    service = _service(session, host.id, 2222, "secure-shell")
    linked = Credential(
        username="Operator", secret="never-list-secret",
        notes="private notes " * 100 + "Full-note-needle", engagement_id=TEST_ENGAGEMENT_ID,
    )
    unlinked = Credential(username="standalone", kind=CredKind.token, engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([linked, unlinked])
    session.flush()
    linked_id, unlinked_id = linked.id, unlinked.id
    session.add(CredentialService(
        credential_id=linked_id, service_id=service.id, engagement_id=TEST_ENGAGEMENT_ID,
    ))
    session.commit()

    rows, total = credential_summaries(session, engagement_id=TEST_ENGAGEMENT_ID)
    assert total == 2
    summary = next(row for row in rows if row.id == linked_id)
    assert (summary.host_count, summary.service_count) == (0, 1)
    assert summary.notes_preview == ("private notes " * 100)[:160]
    assert vars(summary).keys() == {"id", "kind", "username", "notes_preview", "host_count", "service_count"}
    for query in ("OPERATOR", "password", "FULL-NOTE-NEEDLE", "10.42.0.7", "10.42.0.7:2222/tcp", "secure-shell"):
        matches, total = credential_summaries(session, query, engagement_id=TEST_ENGAGEMENT_ID)
        assert [row.id for row in matches] == [linked_id]
        assert total == 2
    assert credential_summaries(session, "never-list-secret", engagement_id=TEST_ENGAGEMENT_ID)[0] == []
    assert [row.id for row in credential_summaries(session, scope="linked", engagement_id=TEST_ENGAGEMENT_ID)[0]] == [linked_id]
    assert [row.id for row in credential_summaries(session, scope="unlinked", engagement_id=TEST_ENGAGEMENT_ID)[0]] == [unlinked_id]
    assert [row.id for row in credential_summaries(session, kind="token", engagement_id=TEST_ENGAGEMENT_ID)[0]] == [unlinked_id]
    assert credential_summaries(session, scope="unknown", engagement_id=TEST_ENGAGEMENT_ID) == ([], 2)


def test_credential_lists_never_select_secrets_and_detail_loads_only_selected_links(session: Session) -> None:
    host = _host(session, "10.0.0.1")
    own_service = _service(session, host.id, 22, "ssh")
    unrelated_host = _host(session, "10.0.0.2")
    _service(session, unrelated_host.id, 443, "https")
    selected = Credential(username="selected", secret="selected-secret", engagement_id=TEST_ENGAGEMENT_ID)
    unrelated = Credential(username="unrelated", secret="unrelated-secret" * 10000, engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([selected, unrelated])
    session.flush()
    selected_id, unrelated_id = selected.id, unrelated.id
    own_service_id = own_service.id
    session.add_all([
        CredentialHost(credential_id=selected_id, host_id=host.id, engagement_id=TEST_ENGAGEMENT_ID),
        CredentialHost(credential_id=unrelated_id, host_id=unrelated_host.id, engagement_id=TEST_ENGAGEMENT_ID),
    ])
    session.commit()
    session.expunge_all()
    statements = []

    def record_sql(connection, cursor, statement, parameters, context, executemany) -> None:
        statements.append(statement)

    engine = session.get_bind()
    event.listen(engine, "before_cursor_execute", record_sql)
    try:
        credential_summaries(session, engagement_id=TEST_ENGAGEMENT_ID)
        credential_summaries(session, "selected", engagement_id=TEST_ENGAGEMENT_ID)
    finally:
        event.remove(engine, "before_cursor_execute", record_sql)
    assert statements
    assert all("credential.secret" not in statement.lower() for statement in statements)
    assert not any(isinstance(value, Credential) for value in session.identity_map.values())
    loaded_credentials = []
    loaded_services = []

    def record_credential(value, context) -> None:
        loaded_credentials.append(value.id)

    def record_service(value, context) -> None:
        loaded_services.append(value.id)

    event.listen(Credential, "load", record_credential)
    event.listen(Service, "load", record_service)
    try:
        detail = credential_view(session, selected_id, engagement_id=TEST_ENGAGEMENT_ID)
    finally:
        event.remove(Credential, "load", record_credential)
        event.remove(Service, "load", record_service)
    assert detail is not None and detail.secret == "selected-secret"
    assert [service.service_id for service in detail.pickable_services] == [own_service_id]
    assert loaded_credentials == [selected_id]
    assert set(loaded_services) == {own_service_id}
