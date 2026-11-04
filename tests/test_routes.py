from __future__ import annotations

import json
import re

import pytest
from starlette.testclient import TestClient

from tests.fixtures import SCAN_A, SCAN_B


def _create_host(client: TestClient, ip: str = "10.0.0.5") -> str:
    response = client.post("/hosts", data={"ip": ip}, follow_redirects=False)
    assert response.status_code == 303
    return response.headers["location"]


def _upload(client: TestClient, content: str, filename: str) -> None:
    response = client.post(
        "/scans", files={"file": (filename, content, "text/xml")},
        data={"tool": "nmap"}, follow_redirects=False,
    )
    assert response.status_code == 303


@pytest.mark.parametrize("accept", ["text/html", "*/*", ""])
def test_page_shell_embeds_same_safe_data_and_local_assets(client: TestClient, accept: str) -> None:
    query = '</script><script>alert("x")</script>&>\u2028\u2029tail'
    expected = client.get("/search", params={"q": query}).json()
    response = client.get("/search", params={"q": query}, headers={"Accept": accept})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["vary"] == "Accept"
    assert '<div id="root"></div>' in response.text
    assert 'src="/static/ui/app.js"' in response.text
    assert 'href="/static/ui/app.css"' in response.text
    match = re.search(r'<script id="page-data" type="application/json">(.*?)</script>', response.text)
    assert match is not None
    embedded = match.group(1)
    assert not any(character in embedded for character in "<>&\u2028\u2029")
    assert json.loads(embedded) == expected
    assert expected["q"] == query
    assert "request" not in expected


@pytest.mark.parametrize(
    ("path", "key"),
    [("/", "rows"), ("/search", "results"), ("/credentials", "credentials"),
     ("/scans", "scans"), ("/diff", "result"), ("/operations", "operations")],
)
def test_page_json_contexts(client: TestClient, path: str, key: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["vary"] == "Accept"
    data = response.json()
    assert key in data
    assert "request" not in data
    assert data["per_page_choices"] == ["10", "25", "50", "all"]


def test_missing_host_404(client: TestClient) -> None:
    response = client.get("/hosts/999999")
    assert response.status_code == 404
    assert response.json()["detail"] == "host not found"


def test_create_host_redirects_to_detail(client: TestClient) -> None:
    path = _create_host(client)
    assert path.startswith("/hosts/")
    detail = client.get(path)
    assert detail.status_code == 200
    data = detail.json()
    assert data["host"]["ip"] == "10.0.0.5"
    assert data["host"]["first_seen"]
    assert data["hostnames"] == []
    assert data["services"] == []
    assert data["host_notes"] == []
    assert data["host_credentials"] == []
    assert data["host_ann"] is None
    assert "request" not in data


def test_create_host_rejects_bad_ip(client: TestClient) -> None:
    response = client.post("/hosts", data={"ip": "not-an-ip"}, follow_redirects=False)
    assert response.status_code == 400
    assert "not a valid" in response.json()["detail"]


def test_delete_host_redirects_home(client: TestClient) -> None:
    path = _create_host(client, "10.0.0.6")
    response = client.post(f"{path}/delete", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.get(path).status_code == 404


def test_export_csv_headers(client: TestClient) -> None:
    response = client.get("/export/hosts.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]


def test_create_credential_lists_it(client: TestClient) -> None:
    response = client.post(
        "/credentials", data={"kind": "password", "username": "root", "secret": "toor"},
    )
    assert response.status_code == 200
    credential = response.json()["credentials"][0]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    assert credential["kind"] == "password"


def test_upload_scan_then_host_appears(client: TestClient) -> None:
    _upload(client, SCAN_A, "a.xml")
    row = client.get("/").json()["rows"][0]
    assert row["ip"] == "10.0.0.1"
    assert row["hostnames"] == ["a.example"]
    assert row["open_ports"] == [22, 80]
    assert row["open_services"] == [[22, "ssh"], [80, "http"]]
    detail = client.get(f'/hosts/{row["id"]}').json()
    assert [service["port"] for service in detail["services"]] == [22, 80]
    assert detail["services"][0]["version"] == "8.9"
    assert detail["hostnames"][0][1] == "a.example"
    scan = client.get("/scans").json()["scans"][0]
    assert scan["filename"] == "a.xml"
    assert scan["imported_at"]


def test_diff_serializes_scans_and_changes(client: TestClient) -> None:
    _upload(client, SCAN_A, "a.xml")
    _upload(client, SCAN_B, "b.xml")
    scans = client.get("/scans").json()["scans"]
    ids = {scan["filename"]: scan["id"] for scan in scans}
    data = client.get("/diff", params={"a": ids["a.xml"], "b": ids["b.xml"]}).json()
    assert data["a"] == ids["a.xml"]
    assert data["b"] == ids["b.xml"]
    assert data["result"]["scan_a"]["filename"] == "a.xml"
    assert data["result"]["scan_b"]["filename"] == "b.xml"
    changes = {entry["port"]: entry for entry in data["result"]["entries"]}
    assert changes[22]["kind"] == "changed"
    assert changes[443]["kind"] == "added"


def test_edit_host_rejects_duplicate_ip(client: TestClient) -> None:
    _create_host(client, "10.0.0.10")
    path = _create_host(client, "10.0.0.11")
    response = client.post(f"{path}/edit", data={"ip": "10.0.0.10"}, follow_redirects=False)
    assert response.status_code == 409
    assert "already belongs to another host" in response.json()["detail"]
    assert client.get(path).json()["host"]["ip"] == "10.0.0.11"


def test_edit_host_accepts_new_ip(client: TestClient) -> None:
    path = _create_host(client, "10.0.0.12")
    response = client.post(f"{path}/edit", data={"ip": "10.0.0.99"}, follow_redirects=False)
    assert response.status_code == 303
    assert client.get(path).json()["host"]["ip"] == "10.0.0.99"


def test_hostnames_add_and_hide_return_json(client: TestClient) -> None:
    path = _create_host(client)
    response = client.post(f"{path}/hostnames", data={"name": "  API.Internal  "})
    assert response.status_code == 200
    hostname_id, name = response.json()["hostnames"][0]
    assert name == "api.internal"
    deleted = client.post(f"{path}/hostnames/{hostname_id}/delete")
    assert deleted.status_code == 200
    assert deleted.json()["hostnames"] == []
    assert client.get(path).json()["hostnames"] == []


def test_service_mutations_return_resolved_json(client: TestClient) -> None:
    path = _create_host(client)
    created = client.post(f"{path}/services", data={"port": "443", "service_name": "https"})
    assert created.status_code == 200
    service = created.json()["services"][0]
    assert service["port"] == 443
    assert service["service_name"] == "https"
    assert service["manual"] is True
    service_id = service["service_id"]
    edited = client.post(f"/services/{service_id}/edit", data={
        "state": "open", "service_name": "https", "product": "nginx",
        "status": "interesting", "tags": "web, tls",
    })
    assert edited.status_code == 200
    resolved = edited.json()["services"][0]
    assert resolved["product"] == "nginx"
    assert resolved["annotation"]["status"] == "interesting"
    assert resolved["annotation"]["tags"] == ["web", "tls"]
    deleted = client.post(f"/services/{service_id}/delete")
    assert deleted.status_code == 200
    assert deleted.json()["services"] == []


def test_notes_and_annotation_round_trip_in_host_context(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    created = client.post("/notes", data={"host_id": host_id, "title": "  Recon  ", "body_md": "raw\nbody"})
    assert created.status_code == 200
    note = created.json()["notes"][0]
    assert note["title"] == "Recon"
    assert note["body_md"] == "raw\nbody"
    assert note["created_at"]
    edited = client.post(f'/notes/{note["id"]}/edit', data={"title": "Updated", "body_md": "new body"})
    assert edited.json()["notes"][0]["body_md"] == "new body"
    saved = client.post("/annotation", data={"host_id": host_id, "status": "interesting", "tags": "pivot, web"})
    assert saved.status_code == 200
    assert saved.json()["ann"]["status"] == "interesting"
    annotation = client.get("/annotation", params={"host_id": host_id})
    assert annotation.status_code == 200
    assert annotation.json()["ann"]["tags"] == ["pivot", "web"]
    detail = client.get(path).json()
    assert detail["host_notes"][0]["title"] == "Updated"
    assert detail["host_ann"]["status"] == "interesting"
    deleted = client.post(f'/notes/{note["id"]}/delete')
    assert deleted.status_code == 200
    assert deleted.json()["notes"] == []


def test_linked_credentials_serialize_hosts_and_services(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    service_id = client.post(f"{path}/services", data={"port": "22", "service_name": "ssh"}).json()["services"][0]["service_id"]
    credential_id = client.post("/credentials", data={"username": "root", "secret": "toor"}).json()["credentials"][0]["id"]
    linked = client.post(f"/credentials/{credential_id}/link/host", data={"host_id": host_id})
    assert linked.status_code == 200
    credential = linked.json()["credentials"][0]
    assert credential["hosts"][0]["ip"] == "10.0.0.5"
    assert credential["pickable_services"][0]["service_id"] == service_id
    linked_service = client.post(f"/credentials/{credential_id}/link/service", data={"service_id": str(service_id)})
    assert linked_service.json()["credentials"][0]["services"][0]["name"] == "ssh"
    detail = client.get(path).json()
    assert detail["host_credentials"][0]["id"] == credential_id
    edited = client.post(f"/credentials/{credential_id}/edit", data={"host_id": host_id, "username": "admin", "secret": "changed"})
    assert edited.json()["host_credentials"][0]["username"] == "admin"
    unlinked_service = client.post(f"/credentials/{credential_id}/unlink/service/{service_id}")
    assert unlinked_service.json()["credentials"][0]["services"] == []
    unlinked_host = client.post(f"/credentials/{credential_id}/unlink/host/{host_id}")
    assert unlinked_host.json()["credentials"][0]["hosts"] == []
    deleted = client.post(f"/credentials/{credential_id}/delete")
    assert deleted.json()["credentials"] == []


def test_unlink_host_removes_only_its_credential_service_links(client: TestClient) -> None:
    host_path = _create_host(client)
    other_path = _create_host(client, "10.0.0.6")
    host_id = int(host_path.rsplit("/", 1)[1])
    other_id = int(other_path.rsplit("/", 1)[1])
    service_ids: list[int] = []
    for path, port in ((host_path, 22), (host_path, 443), (other_path, 22)):
        services = client.post(f"{path}/services", data={"port": str(port)}).json()["services"]
        service_ids.append(next(service["service_id"] for service in services if service["port"] == port))
    credential_id = client.post("/credentials", data={"username": "root", "secret": "toor"}).json()["credentials"][0]["id"]
    other_credential_id = client.post("/credentials", data={"username": "admin", "secret": "other"}).json()["credentials"][0]["id"]
    for cid in (credential_id, other_credential_id):
        for hid in (host_id, other_id):
            client.post(f"/credentials/{cid}/link/host", data={"host_id": str(hid)})
        for sid in service_ids:
            client.post(f"/credentials/{cid}/link/service", data={"service_id": str(sid)})

    response = client.post(f"/credentials/{credential_id}/unlink/host/{host_id}")
    assert response.status_code == 200
    credentials = {credential["id"]: credential for credential in response.json()["credentials"]}
    credential = credentials[credential_id]
    assert [host["host_id"] for host in credential["hosts"]] == [other_id]
    assert [service["service_id"] for service in credential["services"]] == [service_ids[2]]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    other = credentials[other_credential_id]
    assert {host["host_id"] for host in other["hosts"]} == {host_id, other_id}
    assert {service["service_id"] for service in other["services"]} == set(service_ids)

    # Re-linking the host must not resurrect its old service associations.
    client.post(f"/credentials/{credential_id}/unlink/host/{host_id}")
    client.post(f"/credentials/{credential_id}/link/host", data={"host_id": str(host_id)})
    persisted = {credential["id"]: credential for credential in client.get("/credentials").json()["credentials"]}
    assert [service["service_id"] for service in persisted[credential_id]["services"]] == [service_ids[2]]


def test_search_serializes_all_result_sources(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    client.post(f"{path}/hostnames", data={"name": "needle.internal"})
    client.post("/notes", data={"host_id": host_id, "title": "Needle", "body_md": "needle evidence"})
    client.post("/credentials", data={"username": "needle", "secret": "secret"})
    data = client.get("/search", params={"q": " needle "}).json()
    assert data["q"] == "needle"
    assert data["results"]["hosts"][0]["ip"] == "10.0.0.5"
    assert data["results"]["notes"][0]["href"] == path
    assert data["results"]["credentials"][0]["username"] == "needle"
