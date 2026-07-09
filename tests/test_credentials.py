from __future__ import annotations

from sqlmodel import Session

from penrecon.models import (
    CredKind,
    Credential,
    CredentialHost,
    CredentialService,
    Host,
    Service,
)
from penrecon.queries import credential_views, credentials_for_host


def _host(session: Session, ip: str) -> Host:
    h = Host(ip=ip)
    session.add(h)
    session.commit()
    session.refresh(h)
    return h


def _service(session: Session, host_id: int, port: int, name: str | None = None) -> Service:
    s = Service(host_id=host_id, port=port, proto="tcp", m_service_name=name)
    session.add(s)
    session.commit()
    session.refresh(s)
    return s


def test_credential_view_lists_host_and_service_links(session: Session) -> None:
    h = _host(session, "10.0.0.1")
    svc = _service(session, h.id, 22, "ssh")  # type: ignore[arg-type]
    c = Credential(kind=CredKind.password, username="root", secret="toor")
    session.add(c)
    session.commit()
    session.refresh(c)
    session.add(CredentialHost(credential_id=c.id, host_id=h.id))  # type: ignore[arg-type]
    session.add(CredentialService(credential_id=c.id, service_id=svc.id))  # type: ignore[arg-type]
    session.commit()

    views = credential_views(session)
    assert len(views) == 1
    v = views[0]
    assert (v.username, v.secret) == ("root", "toor")
    assert [x.ip for x in v.hosts] == ["10.0.0.1"]
    assert [(s.port, s.proto, s.name) for s in v.services] == [(22, "tcp", "ssh")]


def test_credentials_for_host_includes_service_only_links(session: Session) -> None:
    h = _host(session, "10.0.0.2")
    svc = _service(session, h.id, 445, "microsoft-ds")  # type: ignore[arg-type]
    c = Credential(kind=CredKind.hash, secret="aad3b435:31d6cfe0")
    session.add(c)
    session.commit()
    session.refresh(c)
    session.add(CredentialService(credential_id=c.id, service_id=svc.id))  # type: ignore[arg-type]
    session.commit()

    # tied to the host only through its service, never linked to the host directly
    got = credentials_for_host(session, h.id)  # type: ignore[arg-type]
    assert len(got) == 1 and got[0].secret == "aad3b435:31d6cfe0"

    other = _host(session, "10.0.0.3")
    assert credentials_for_host(session, other.id) == []  # type: ignore[arg-type]


def test_pickable_services_scoped_to_linked_hosts(session: Session) -> None:
    h1 = _host(session, "10.0.0.10")
    s_pick = _service(session, h1.id, 22, "ssh")  # type: ignore[arg-type]
    s_linked = _service(session, h1.id, 80, "http")  # type: ignore[arg-type]
    h2 = _host(session, "10.0.0.11")
    _service(session, h2.id, 3389, "rdp")  # unlinked host — must not appear  # type: ignore[arg-type]

    c = Credential(kind=CredKind.password, username="root", secret="toor")
    session.add(c)
    session.commit()
    session.refresh(c)
    session.add(CredentialHost(credential_id=c.id, host_id=h1.id))  # type: ignore[arg-type]
    session.add(CredentialService(credential_id=c.id, service_id=s_linked.id))  # type: ignore[arg-type]
    session.commit()

    v = credential_views(session)[0]
    # only h1's services, minus the already-linked one → just s_pick
    assert [s.service_id for s in v.pickable_services] == [s_pick.id]

    # a credential with no host linked can pick nothing
    c2 = Credential(kind=CredKind.password, username="x", secret="y")
    session.add(c2)
    session.commit()
    assert credential_views(session)[0].pickable_services == []
