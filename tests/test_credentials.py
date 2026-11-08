from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session
from sqlmodel import select
from starlette.testclient import TestClient

from penrecon.ingest import ingest_scan
from penrecon.queries import resolved_services
from tests.fixtures import api_url, SCAN_A

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


def test_credential_api_openapi_describes_forms_and_nested_projections(client: TestClient) -> None:
    document = client.get("/openapi.json").json()
    paths = document["paths"]
    schemas = document["components"]["schemas"]
    base = "/api/credentials"
    for path, methods in paths.items():
        if not path.startswith(base):
            continue
        assert "{engagement_id}" not in path
        for operation in methods.values():
            engagement = next(parameter for parameter in operation["parameters"] if parameter["name"] == "engagement_id")
            assert engagement["in"] == "query"
            assert engagement["required"] is True

    def resolve(schema: dict) -> dict:
        return schemas[schema["$ref"].rsplit("/", 1)[1]] if "$ref" in schema else schema

    def success_schema(path: str, method: str) -> dict:
        return resolve(paths[path][method]["responses"]["200"]["content"]["application/json"]["schema"])

    listing = success_schema(base, "get")
    assert set(listing["properties"]) == {"credentials", "total", "kinds", "q", "kind", "scope"}
    summary = resolve(listing["properties"]["credentials"]["items"])
    assert set(summary["properties"]) == {
        "id", "kind", "username", "notes_preview", "host_count", "service_count",
    }
    detail = success_schema(base + "/{cred_id}", "get")
    credential = resolve(detail["properties"]["credential"])
    assert set(credential["properties"]) == {
        "id", "kind", "username", "secret", "notes", "created_at",
        "hosts", "services", "pickable_services",
    }
    hosts = resolve(credential["properties"]["hosts"]["items"])
    assert set(hosts["properties"]) == {"host_id", "ip"}
    for field in ("services", "pickable_services"):
        service = resolve(credential["properties"][field]["items"])
        assert set(service["properties"]) == {"service_id", "host_id", "ip", "port", "proto", "name"}

    fields_by_operation = {
        ("", "post"): {"kind", "username", "secret", "notes", "host_ids", "service_ids"},
        ("/{cred_id}", "put"): {"kind", "username", "secret", "notes", "host_id"},
        ("/{cred_id}", "delete"): {"host_id"},
        ("/{cred_id}/hosts", "patch"): {"host_id"},
        ("/{cred_id}/services", "patch"): {"service_id"},
    }
    for (suffix, method), fields in fields_by_operation.items():
        operation = paths[base + suffix][method]
        form = resolve(operation["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"])
        assert set(form["properties"]) == fields
    for suffix, method in (
        ("", "post"), ("/{cred_id}", "put"), ("/{cred_id}", "delete"),
        ("/{cred_id}/hosts", "patch"), ("/{cred_id}/services", "patch"),
        ("/{cred_id}/hosts/{host_id}", "delete"),
        ("/{cred_id}/services/{service_id}", "delete"),
    ):
        mutation = success_schema(base + suffix, method)
        assert "ok" in mutation["required"]
        assert paths[base + suffix][method]["responses"]["422"]["content"]["application/json"]["schema"]["$ref"].endswith("/ErrorResponse")


def test_credential_api_json_only_association_workflow(client: TestClient) -> None:
    assert client.post(
        api_url("/scans"), files={"file": ("scan.xml", SCAN_A, "text/xml")},
        data={"tool": "nmap"},
    ).status_code == 200
    hosts = client.get(api_url("/options/hosts")).json()["hosts"]
    host_id = hosts[0]["id"]
    services = client.get(api_url(f"/options/hosts/{host_id}/services")).json()["services"]
    service_id = next(service["service_id"] for service in services if service["port"] == 22)
    base = api_url("/credentials")
    assert client.post(base, data={
        "username": "operator", "secret": "private-secret-marker", "notes": "triage notes",
    }).json() == {"ok": True}
    listing = client.get(base, headers={"Accept": "text/html"})
    assert listing.status_code == 200
    assert listing.headers["content-type"].startswith("application/json")
    assert listing.headers["cache-control"] == "no-store"
    assert "private-secret-marker" not in listing.text
    assert "secret" not in listing.json()["credentials"][0]
    credential_id = listing.json()["credentials"][0]["id"]
    path = api_url(f"/credentials/{credential_id}")
    detail = client.get(path)
    assert detail.headers["cache-control"] == "no-store"
    assert detail.json()["credential"]["secret"] == "private-secret-marker"
    assert detail.json()["credential"]["pickable_services"] == []

    assert client.patch(api_url(f"/credentials/{credential_id}/services"), data={"service_id": service_id}).status_code == 422
    assert client.patch(api_url(f"/credentials/{credential_id}/hosts")).status_code == 422
    assert client.patch(api_url(f"/credentials/{credential_id}/hosts"), data={"host_id": host_id}).json() == {"ok": True}
    available = client.get(path).json()["credential"]["pickable_services"]
    assert {service["service_id"] for service in available} == {service["service_id"] for service in services}
    assert client.patch(api_url(f"/credentials/{credential_id}/services"), data={"service_id": service_id}).json() == {"ok": True}
    linked = client.get(path).json()["credential"]
    assert linked["hosts"] == [{"host_id": host_id, "ip": "10.0.0.1"}]
    assert linked["services"] == [{
        "service_id": service_id, "host_id": host_id, "ip": "10.0.0.1",
        "port": 22, "proto": "tcp", "name": "ssh",
    }]
    assert client.put(path, data={"username": "replacement"}).json() == {"ok": True}
    replacement = client.get(path).json()["credential"]
    assert (replacement["kind"], replacement["username"], replacement["secret"], replacement["notes"]) == (
        "password", "replacement", "", "",
    )
    assert replacement["hosts"] == linked["hosts"]
    assert replacement["services"] == linked["services"]
    assert client.delete(api_url(f"/credentials/{credential_id}/services/{service_id}")).json() == {"ok": True}
    assert client.get(path).json()["credential"]["services"] == []
    assert client.patch(api_url(f"/credentials/{credential_id}/services"), data={"service_id": service_id}).status_code == 200
    assert client.delete(api_url(f"/credentials/{credential_id}/hosts/{host_id}")).json() == {"ok": True}
    unlinked = client.get(path).json()["credential"]
    assert unlinked["hosts"] == unlinked["services"] == unlinked["pickable_services"] == []
    assert client.put(path, data={
        "kind": "token", "username": " revised ", "secret": " new secret ", "notes": " updated ",
        "host_id": host_id,
    }).json() == {"ok": True}
    updated = client.get(path).json()["credential"]
    assert (updated["kind"], updated["username"], updated["secret"], updated["notes"]) == (
        "token", "revised", "new secret", "updated",
    )

    created = client.post("/api/engagements", data={"name": "Other engagement"}).json()
    other_id = created["redirect_to"].strip("/").split("/")[1]
    foreign_detail = client.get(api_url(f"/credentials/{credential_id}", other_id))
    assert foreign_detail.status_code == 404
    assert foreign_detail.headers["cache-control"] == "no-store"
    foreign_path = api_url(f"/credentials/{credential_id}", other_id)
    assert client.put(foreign_path, data={"username": "forbidden"}).status_code == 404
    assert client.patch(api_url(f"/credentials/{credential_id}/hosts", other_id), data={"host_id": host_id}).status_code == 404
    assert client.delete(foreign_path).status_code == 404
    assert client.post(api_url(f"/credentials", other_id), data={
        "username": "foreign", "host_ids": [str(host_id)], "service_ids": [str(service_id)],
    }).status_code == 422
    assert client.get(api_url(f"/credentials", other_id)).json()["credentials"] == []
    assert client.request("DELETE", path, data={"host_id": host_id}).json() == {"ok": True}
    assert client.get(path).status_code == 404
    assert client.get(base).json()["credentials"] == []
