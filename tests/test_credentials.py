from __future__ import annotations

from tests.fixtures import TEST_ENGAGEMENT_ID
from sqlmodel import Session
from sqlmodel import select
from starlette.testclient import TestClient

from penrecon.ingest import ingest_scan
from penrecon.queries.inventory import resolved_services
from tests.fixtures import api_url, SCAN_A

from penrecon.models import (
    CredKind,
    Credential,
    CredentialHost,
    CredentialService,
    Host,
    Service,
)
from penrecon.queries.credentials import credential_service_options, credential_summaries, credential_view, credentials_for_host


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


def test_service_options_scoped_to_linked_hosts(session: Session) -> None:
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

    options = credential_service_options(session, c.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [s.service_id for s in options.services] == [s_pick.id]

    # a credential with no host linked can pick nothing
    c2 = Credential(kind=CredKind.password, username="x", secret="y", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(c2)
    session.commit()
    options = credential_service_options(session, c2.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert options.services == [] and options.total == 0


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
        options = credential_service_options(session, credential.id, engagement_id=TEST_ENGAGEMENT_ID)
        return view.services[0].name, options.services[0].name

    assert names() == ("ssh-new", "http-new")
    assert credential_summaries(session, "ssh-new", engagement_id=TEST_ENGAGEMENT_ID).matched == 1
    assert credential_service_options(session, credential.id, q="http-new", engagement_id=TEST_ENGAGEMENT_ID).total == 1
    services[22].m_service_name = "manual-ssh"
    services[80].m_service_name = "manual-http"
    session.commit()
    assert names() == ("manual-ssh", "manual-http")
    assert credential_summaries(session, "ssh-new", engagement_id=TEST_ENGAGEMENT_ID).matched == 0
    assert credential_summaries(session, "manual-ssh", engagement_id=TEST_ENGAGEMENT_ID).matched == 1
    assert credential_service_options(session, credential.id, q="http-new", engagement_id=TEST_ENGAGEMENT_ID).total == 0
    assert credential_service_options(session, credential.id, q="manual-http", engagement_id=TEST_ENGAGEMENT_ID).total == 1

    services[22].m_service_name = ""
    services[80].m_service_name = None
    session.commit()
    assert names() == ("ssh-new", "http-new")
    assert credential_summaries(session, "ssh-new", engagement_id=TEST_ENGAGEMENT_ID).matched == 1
    assert credential_service_options(session, credential.id, q="http-new", engagement_id=TEST_ENGAGEMENT_ID).total == 1

    unnamed = SCAN_A.replace('name="ssh"', 'name=""').replace('name="http"', 'name=""')
    ingest_scan(session, unnamed.encode(), "unnamed.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert names() == (None, None)
    assert credential_summaries(session, "ssh-new", engagement_id=TEST_ENGAGEMENT_ID).matched == 0
    assert credential_service_options(session, credential.id, q="http-new", engagement_id=TEST_ENGAGEMENT_ID).total == 0
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

    result = credential_summaries(session, engagement_id=TEST_ENGAGEMENT_ID)
    assert result.total == result.matched == 2
    summary = next(row for row in result.credentials if row.id == linked_id)
    assert (summary.host_count, summary.service_count) == (0, 1)
    assert summary.notes_preview == ("private notes " * 100)[:160]
    assert vars(summary).keys() == {"id", "kind", "username", "notes_preview", "host_count", "service_count"}
    for query in ("OPERATOR", "password", "FULL-NOTE-NEEDLE", "10.42.0.7", "10.42.0.7:2222/tcp", "secure-shell"):
        result = credential_summaries(session, query, engagement_id=TEST_ENGAGEMENT_ID)
        assert [row.id for row in result.credentials] == [linked_id]
        assert result.total == 2 and result.matched == 1
    assert credential_summaries(session, "never-list-secret", engagement_id=TEST_ENGAGEMENT_ID).credentials == []
    assert [row.id for row in credential_summaries(session, scope="linked", engagement_id=TEST_ENGAGEMENT_ID).credentials] == [linked_id]
    assert [row.id for row in credential_summaries(session, scope="unlinked", engagement_id=TEST_ENGAGEMENT_ID).credentials] == [unlinked_id]
    assert [row.id for row in credential_summaries(session, kind="token", engagement_id=TEST_ENGAGEMENT_ID).credentials] == [unlinked_id]
    result = credential_summaries(session, scope="unknown", engagement_id=TEST_ENGAGEMENT_ID)
    assert result.credentials == [] and result.total == 2 and result.matched == 0


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
    assert set(listing["properties"]) == {
        "credentials", "total", "matched", "page", "pages", "per", "kinds", "q", "kind", "scope",
    }
    summary = resolve(listing["properties"]["credentials"]["items"])
    assert set(summary["properties"]) == {
        "id", "kind", "username", "notes_preview", "host_count", "service_count",
    }
    detail = success_schema(base + "/{cred_id}", "get")
    credential = resolve(detail["properties"]["credential"])
    assert set(credential["properties"]) == {
        "id", "kind", "username", "secret", "notes", "created_at",
        "hosts", "services",
    }
    hosts = resolve(credential["properties"]["hosts"]["items"])
    assert set(hosts["properties"]) == {"host_id", "ip"}
    options = success_schema(base + "/{cred_id}/options/services", "get")
    assert set(options["properties"]) == {"services", "total", "page", "pages", "per"}
    for collection in (credential, options):
        service = resolve(collection["properties"]["services"]["items"])
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
    assert "pickable_services" not in detail.json()["credential"]
    options_path = api_url(f"/credentials/{credential_id}/options/services")
    assert client.get(options_path).json()["services"] == []

    assert client.patch(api_url(f"/credentials/{credential_id}/services"), data={"service_id": service_id}).status_code == 422
    assert client.patch(api_url(f"/credentials/{credential_id}/hosts")).status_code == 422
    assert client.patch(api_url(f"/credentials/{credential_id}/hosts"), data={"host_id": host_id}).json() == {"ok": True}
    available = client.get(options_path).json()["services"]
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
    assert unlinked["hosts"] == unlinked["services"] == []
    assert client.get(options_path).json()["services"] == []
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
    foreign_options = client.get(api_url(f"/credentials/{credential_id}/options/services", other_id))
    assert foreign_options.status_code == 404
    assert foreign_options.headers["cache-control"] == "no-store"
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
    missing_options = client.get(options_path)
    assert missing_options.status_code == 404
    assert missing_options.headers["cache-control"] == "no-store"
    assert client.get(base).json()["credentials"] == []


def test_credential_pages_count_filter_clamp_and_isolate(client: TestClient) -> None:
    for index in range(27):
        assert client.post(api_url("/credentials"), data={
            "username": f"operator-{index:02}", "kind": "token" if index < 12 else "password",
            "secret": "never-return-this",
        }).status_code == 200
    other = client.post("/api/engagements", data={"name": "Other"}).json()["redirect_to"].split("/")[2]
    assert client.post(api_url("/credentials", other), data={"username": "operator-foreign"}).status_code == 200
    default = client.get(api_url("/credentials"))
    assert default.headers["cache-control"] == "no-store"
    assert (default.json()["total"], default.json()["matched"], default.json()["per"]) == (27, 27, "25")
    assert len(default.json()["credentials"]) == 25
    assert "never-return-this" not in default.text
    engagement = {"engagement_id": TEST_ENGAGEMENT_ID}
    last = client.get(api_url("/credentials"), params=engagement | {"page": 99, "per": "10"}).json()
    assert (last["total"], last["matched"], last["page"], last["pages"], last["per"]) == (27, 27, 3, 3, "10")
    assert [row["username"] for row in last["credentials"]] == [f"operator-{index:02}" for index in range(6, -1, -1)]
    filtered = client.get(api_url("/credentials"), params=engagement | {
        "filter": "OPERATOR", "kind": "token", "scope": "unlinked", "page": 99, "per": "10",
    }).json()
    assert (filtered["total"], filtered["matched"], filtered["page"], filtered["pages"]) == (27, 12, 2, 2)
    assert [row["username"] for row in filtered["credentials"]] == ["operator-01", "operator-00"]
    empty = client.get(api_url("/credentials"), params=engagement | {"filter": "missing", "page": -10}).json()
    assert (empty["total"], empty["matched"], empty["page"], empty["pages"]) == (27, 0, 1, 1)
    assert empty["credentials"] == []
    all_rows = client.get(api_url("/credentials"), params=engagement | {"per": "all", "page": 99}).json()
    assert len(all_rows["credentials"]) == 27 and (all_rows["page"], all_rows["pages"], all_rows["per"]) == (1, 1, "all")
    assert client.get(api_url("/credentials"), params=engagement | {"per": "invalid"}).json()["per"] == "25"


def test_credential_search_preserves_unicode_literals_and_field_boundaries(session: Session) -> None:
    host = _host(session, "10.60.0.1")
    service = _service(session, host.id, 443, "Straße%_TLS")
    credential = Credential(
        username="ÜSER", kind=CredKind.token, notes="prefix " * 1000 + "ΩMEGA",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    session.add(credential)
    session.flush()
    credential_id = credential.id
    session.add(CredentialHost(
        credential_id=credential_id, host_id=host.id, engagement_id=TEST_ENGAGEMENT_ID,
    ))
    session.add(CredentialService(
        credential_id=credential_id, service_id=service.id, engagement_id=TEST_ENGAGEMENT_ID,
    ))
    session.commit()
    for query in (
        "üser", "ωmega", "straße%_tls", "%_", "ÜSER TOKEN PREFIX",
        "ωmega 10.60.0.1 10.60.0.1:443/tcp straße",
    ):
        result = credential_summaries(session, query, engagement_id=TEST_ENGAGEMENT_ID)
        assert [row.id for row in result.credentials] == [credential_id]
    for query in ("STRASSE", "tls%", "ωmega 10.60.0.1:443"):
        assert credential_summaries(session, query, engagement_id=TEST_ENGAGEMENT_ID).matched == 0
    assert credential_service_options(
        session, credential_id, q="straße%_", engagement_id=TEST_ENGAGEMENT_ID,
    ).total == 0
    session.delete(session.exec(select(CredentialService).where(
        CredentialService.credential_id == credential_id,
    )).one())
    session.commit()
    for query, expected in (("straße%_", 1), ("STRASSE", 0), ("TLS%", 0), ("%_", 1)):
        assert credential_service_options(
            session, credential_id, q=query, engagement_id=TEST_ENGAGEMENT_ID,
        ).total == expected


def test_credential_pages_break_timestamp_ties_by_id(session: Session) -> None:
    from datetime import datetime

    credentials = [
        Credential(username=str(index), created_at=datetime(2026, 1, 1), engagement_id=TEST_ENGAGEMENT_ID)
        for index in range(12)
    ]
    session.add_all(credentials)
    session.commit()
    result = credential_summaries(session, page=2, per_page=10, engagement_id=TEST_ENGAGEMENT_ID)
    assert [row.username for row in result.credentials] == ["1", "0"]
    assert (result.total, result.matched, result.page, result.pages) == (12, 12, 2, 2)


def test_host_credentials_only_include_displayed_host_links(session: Session) -> None:
    hosts = [_host(session, ip) for ip in ("10.70.0.1", "10.70.0.2")]
    services = [_service(session, host.id, 22, "ssh") for host in hosts]
    credential = Credential(username="shared", secret="editable", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(credential)
    session.flush()
    credential_id = credential.id
    for host, service in zip(hosts, services):
        session.add(CredentialHost(
            credential_id=credential_id, host_id=host.id, engagement_id=TEST_ENGAGEMENT_ID,
        ))
        session.add(CredentialService(
            credential_id=credential_id, service_id=service.id, engagement_id=TEST_ENGAGEMENT_ID,
        ))
    session.commit()
    for host, service in zip(hosts, services):
        result = credentials_for_host(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
        assert len(result) == 1 and result[0].secret == "editable"
        assert [link.host_id for link in result[0].hosts] == [host.id]
        assert [link.service_id for link in result[0].services] == [service.id]


def test_service_options_page_filter_and_link_transitions(client: TestClient) -> None:
    assert client.post(api_url("/hosts"), data={"ip": "10.80.0.1"}).status_code == 200
    host_id = client.get(api_url("/options/hosts")).json()["hosts"][0]["id"]
    for port in range(1000, 1012):
        assert client.post(api_url(f"/hosts/{host_id}/services"), data={
            "port": port, "service_name": "pick-name", "product": "not-searchable-product",
        }).status_code == 200
    assert client.post(api_url("/credentials"), data={
        "username": "operator", "host_ids": [str(host_id)],
    }).status_code == 200
    credential_id = client.get(api_url("/credentials")).json()["credentials"][0]["id"]
    endpoint = api_url(f"/credentials/{credential_id}/options/services")
    engagement = {"engagement_id": TEST_ENGAGEMENT_ID}
    response = client.get(endpoint, params=engagement | {"page": 50, "per": "10", "q": "PICK-NAME"})
    assert response.headers["cache-control"] == "no-store"
    options = response.json()
    assert (options["total"], options["page"], options["pages"], options["per"]) == (12, 2, 2, "10")
    assert [service["port"] for service in options["services"]] == [1010, 1011]
    all_services = client.get(endpoint, params=engagement | {"per": "all", "page": 9}).json()
    assert (all_services["total"], all_services["page"], all_services["pages"], all_services["per"]) == (12, 1, 1, "all")
    assert len(all_services["services"]) == 12
    assert client.get(endpoint, params=engagement | {"q": "not-searchable-product"}).json()["total"] == 0
    assert client.get(endpoint, params=engagement | {"q": "10.80.0.1:1003/TCP PICK"}).json()["services"][0]["port"] == 1003
    selected = options["services"][0]["service_id"]
    assert client.patch(api_url(f"/credentials/{credential_id}/services"), data={"service_id": selected}).status_code == 200
    assert client.get(endpoint).json()["total"] == 11
    assert client.get(endpoint, params=engagement | {"q": ":1010/tcp"}).json()["services"] == []
    assert client.delete(api_url(f"/credentials/{credential_id}/services/{selected}")).status_code == 200
    assert client.get(endpoint).json()["total"] == 12
    assert client.delete(api_url(f"/credentials/{credential_id}/hosts/{host_id}")).status_code == 200
    empty = client.get(endpoint, params=engagement | {"page": 99}).json()
    assert (empty["services"], empty["total"], empty["page"], empty["pages"]) == ([], 0, 1, 1)
