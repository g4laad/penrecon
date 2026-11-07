from __future__ import annotations

import json
import re
from os import utime
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from sqlmodel import Session

from tests.fixtures import SCAN_A, SCAN_B
from tests.fixtures import ENGAGEMENT_PREFIX

def _assert_outcome(response, *, redirect_to: str | None = None) -> None:
    assert response.status_code == 200
    assert "location" not in response.headers
    assert response.json() == ({"ok": True, "redirect_to": redirect_to} if redirect_to else {"ok": True})


def _create_service(client: TestClient, path: str, **fields) -> dict:
    _assert_outcome(client.post(f"{path}/services", data=fields, follow_redirects=False))
    return next(service for service in client.get(path).json()["services"] if service["port"] == int(fields["port"]))


def _create_credential(client: TestClient, **fields) -> dict:
    _assert_outcome(client.post(ENGAGEMENT_PREFIX + "/credentials", data=fields, follow_redirects=False))
    return next(credential for credential in client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"]
                if credential["username"] == fields.get("username", "").strip())



def _create_host(client: TestClient, ip: str = "10.0.0.5") -> str:
    response = client.post(ENGAGEMENT_PREFIX + "/hosts", data={"ip": ip}, follow_redirects=False)
    _assert_outcome(response, redirect_to=response.json()["redirect_to"])
    return response.json()["redirect_to"]


def _upload(client: TestClient, content: str, filename: str) -> None:
    response = client.post(
        ENGAGEMENT_PREFIX + "/scans", files={"file": (filename, content, "text/xml")},
        data={"tool": "nmap"}, follow_redirects=False,
    )
    _assert_outcome(response, redirect_to=ENGAGEMENT_PREFIX + "/scans")


@pytest.mark.parametrize("accept", ["text/html", "*/*", ""])
def test_page_shell_embeds_same_safe_data_and_local_assets(client: TestClient, accept: str) -> None:
    query = '</script><script>alert("x")</script>&>\u2028\u2029tail'
    expected = client.get(ENGAGEMENT_PREFIX + "/search", params={"q": query}).json()
    response = client.get(ENGAGEMENT_PREFIX + "/search", params={"q": query}, headers={"Accept": accept})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["vary"] == "Accept"
    assert '<div id="root"></div>' in response.text
    assets = re.findall(r'(?:src|href)="(/static/ui/[^"]+)"', response.text)
    assert len(assets) == 2
    for asset in assets:
        assert client.get(asset).status_code == 200
    match = re.search(r'<script id="page-data" type="application/json">(.*?)</script>', response.text)
    assert match is not None
    embedded = match.group(1)
    assert not any(character in embedded for character in "<>&\u2028\u2029")
    assert json.loads(embedded) == expected
    assert expected["q"] == query
    assert "request" not in expected


def test_rebuilt_assets_get_new_browser_cache_keys(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from penrecon.web import app as web_app

    assets = tmp_path / "static/ui"
    assets.mkdir(parents=True)
    for name in ("app.js", "app.css"):
        (assets / name).write_text("old bundle")
        utime(assets / name, ns=(1_000_000_000, 1_000_000_000))
    monkeypatch.setattr(web_app, "_HERE", tmp_path)

    def asset_urls() -> list[str]:
        response = client.get(ENGAGEMENT_PREFIX + "/credentials", headers={"Accept": "text/html"})
        assert response.status_code == 200
        return re.findall(r'(?:src|href)="(/static/ui/[^"]+)"', response.text)

    original = asset_urls()
    assert asset_urls() == original
    for name in ("app.js", "app.css"):
        (assets / name).write_text("rebuilt bundle")
        utime(assets / name, ns=(2_000_000_000, 2_000_000_000))
    rebuilt = asset_urls()
    assert len(rebuilt) == len(original) == 2
    assert all(before != after for before, after in zip(original, rebuilt))


@pytest.mark.parametrize(
    ("path", "key"),
    [(ENGAGEMENT_PREFIX + "/", "rows"), (ENGAGEMENT_PREFIX + "/search", "results"), (ENGAGEMENT_PREFIX + "/credentials", "credentials"),
     (ENGAGEMENT_PREFIX + "/scans", "scans"), (ENGAGEMENT_PREFIX + "/diff", "result"), (ENGAGEMENT_PREFIX + "/operations", "operations")],
)
def test_page_json_contexts(client: TestClient, path: str, key: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["vary"] == "Accept"
    data = response.json()
    assert key in data
    assert data["engagement"]["id"] == ENGAGEMENT_PREFIX.rsplit("/", 1)[1]
    assert any(item["id"] == data["engagement"]["id"] for item in data["engagements"])
    assert "request" not in data
    assert "per_page_choices" not in data
    html = client.get(path, headers={"Accept": "text/html"})
    assert html.status_code == 200
    match = re.search(r'<script id="page-data" type="application/json">(.*?)</script>', html.text)
    assert match is not None
    assert "per_page_choices" not in json.loads(match.group(1))


def test_missing_host_404(client: TestClient) -> None:
    response = client.get(ENGAGEMENT_PREFIX + "/hosts/999999")
    assert response.status_code == 404
    assert response.json()["detail"] == "host not found"


def test_create_host_redirects_to_detail(client: TestClient) -> None:
    path = _create_host(client)
    assert path.startswith(ENGAGEMENT_PREFIX + "/hosts/")
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
    response = client.post(ENGAGEMENT_PREFIX + "/hosts", data={"ip": "not-an-ip"}, follow_redirects=False)
    assert response.status_code == 400
    assert set(response.json()["field_errors"]) == {"ip"}


def test_delete_host_redirects_home(client: TestClient) -> None:
    path = _create_host(client, "10.0.0.6")
    response = client.post(f"{path}/delete", follow_redirects=False)
    _assert_outcome(response, redirect_to=ENGAGEMENT_PREFIX + "/")
    assert client.get(path).status_code == 404


def test_export_csv_headers(client: TestClient) -> None:
    response = client.get(ENGAGEMENT_PREFIX + "/export/hosts.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]


def test_create_credential_lists_it(client: TestClient) -> None:
    response = client.post(
        ENGAGEMENT_PREFIX + "/credentials", data={"kind": "password", "username": "root", "secret": "toor"},
    )
    _assert_outcome(response)
    credential = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    assert credential["kind"] == "password"


def test_create_credential_with_multiple_targets_deduplicates_links(client: TestClient) -> None:
    paths = [_create_host(client), _create_host(client, "10.0.0.6")]
    host_ids = [int(path.rsplit("/", 1)[1]) for path in paths]
    service_ids = [
        _create_service(client, path, port="22")["service_id"]
        for path in paths
    ]
    response = client.post(ENGAGEMENT_PREFIX + "/credentials", data={
        "username": " root ", "secret": " toor ", "notes": " shared ",
        "host_ids": [str(hid) for hid in [*host_ids, host_ids[0]]],
        "service_ids": [str(sid) for sid in [*service_ids, service_ids[0]]],
    })
    _assert_outcome(response)
    credential = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    assert credential["notes"] == "shared"
    assert credential["kind"] == "password"
    assert sorted(host["host_id"] for host in credential["hosts"]) == sorted(host_ids)
    assert sorted(service["service_id"] for service in credential["services"]) == sorted(service_ids)
    persisted = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"]
    assert persisted == [credential]
    for path in paths:
        assert client.get(path).json()["host_credentials"][0]["id"] == credential["id"]


@pytest.mark.parametrize("invalid_target", ["unknown_host", "unknown_service", "unselected_host", "no_hosts"])
def test_create_credential_rejects_invalid_targets_without_partial_writes(
    client: TestClient, invalid_target: str,
) -> None:
    path = _create_host(client)
    other_path = _create_host(client, "10.0.0.6")
    host_id = path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22")["service_id"]
    other_service_id = _create_service(client, other_path, port="443")["service_id"]
    _create_credential(client, username="existing")
    existing = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"]
    data = {
        "username": "rejected",
        "host_ids": [host_id],
        "service_ids": [str(service_id)],
    }
    if invalid_target == "unknown_host":
        data["host_ids"].append("999999")
    elif invalid_target == "unknown_service":
        data["service_ids"].append("999999")
    elif invalid_target == "unselected_host":
        data["service_ids"].append(str(other_service_id))
    else:
        data["host_ids"] = []
    response = client.post(ENGAGEMENT_PREFIX + "/credentials", data=data)
    assert response.status_code == 422
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"] == existing
    assert client.get(path).json()["host_credentials"] == []
    assert client.get(other_path).json()["host_credentials"] == []


@pytest.mark.parametrize("data", [{}, {"username": "  ", "secret": "\t", "notes": "notes only"}])
def test_create_credential_rejects_empty_identity(client: TestClient, data: dict[str, str]) -> None:
    response = client.post(ENGAGEMENT_PREFIX + "/credentials", data=data)
    assert response.status_code == 422
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"] == []


@pytest.mark.parametrize("data", [
    {"username": "user only"},
    {"secret": "secret only", "kind": "unknown"},
])
def test_create_credential_preserves_target_free_defaults(client: TestClient, data: dict[str, str]) -> None:
    response = client.post(ENGAGEMENT_PREFIX + "/credentials", data=data)
    _assert_outcome(response)
    credential = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]
    assert credential["kind"] == "password"
    assert credential["username"] == data.get("username", "")
    assert credential["secret"] == data.get("secret", "")
    assert credential["hosts"] == []
    assert credential["services"] == []


def test_upload_scan_then_host_appears(client: TestClient) -> None:
    _upload(client, SCAN_A, "a.xml")
    row = client.get(ENGAGEMENT_PREFIX + "/").json()["rows"][0]
    assert row["ip"] == "10.0.0.1"
    assert row["hostnames"] == ["a.example"]
    assert row["open_services"] == [[22, "ssh"], [80, "http"]]
    detail = client.get(ENGAGEMENT_PREFIX + f'/hosts/{row["id"]}').json()
    assert [service["port"] for service in detail["services"]] == [22, 80]
    assert detail["services"][0]["version"] == "8.9"
    assert detail["hostnames"][0][1] == "a.example"
    scan = client.get(ENGAGEMENT_PREFIX + "/scans").json()["scans"][0]
    assert scan["filename"] == "a.xml"
    assert scan["imported_at"]
    assert {"raw_path", "engagement_id"}.isdisjoint(scan)


@pytest.mark.parametrize(
    ("params", "expected_ips"),
    [
        ({"q": "SSH"}, ["10.0.0.1"]),
        ({"port": "22"}, ["10.0.0.1"]),
        ({"q": "ssh", "port": "443"}, []),
        ({"q": "missing-service"}, []),
    ],
)
def test_inventory_filters_use_private_service_metadata(
    client: TestClient, params: dict[str, str], expected_ips: list[str],
) -> None:
    _upload(client, SCAN_A, "a.xml")
    other_path = _create_host(client)
    client.post(f"{other_path}/services", data={"port": "443", "service_name": "https"})

    data = client.get(ENGAGEMENT_PREFIX + "/", params=params).json()
    assert [row["ip"] for row in data["rows"]] == expected_ips
    assert {"per", "per_page"}.isdisjoint(data)
    for row in data["rows"]:
        assert {"open_ports", "service_names"}.isdisjoint(row)


def test_diff_serializes_scans_and_changes(client: TestClient) -> None:
    _upload(client, SCAN_A, "a.xml")
    _upload(client, SCAN_B, "b.xml")
    scans = client.get(ENGAGEMENT_PREFIX + "/scans").json()["scans"]
    ids = {scan["filename"]: scan["id"] for scan in scans}
    data = client.get(ENGAGEMENT_PREFIX + "/diff", params={"a": ids["a.xml"], "b": ids["b.xml"]}).json()
    assert data["a"] == ids["a.xml"]
    assert data["b"] == ids["b.xml"]
    assert data["result"]["scan_a"]["filename"] == "a.xml"
    assert data["result"]["scan_b"]["filename"] == "b.xml"
    for scan in [*scans, data["result"]["scan_a"], data["result"]["scan_b"]]:
        assert {"raw_path", "engagement_id"}.isdisjoint(scan)
    changes = {entry["port"]: entry for entry in data["result"]["entries"]}
    assert changes[22]["kind"] == "changed"
    assert changes[443]["kind"] == "added"


def test_edit_host_rejects_duplicate_ip(client: TestClient) -> None:
    _create_host(client, "10.0.0.10")
    path = _create_host(client, "10.0.0.11")
    response = client.post(f"{path}/edit", data={"ip": "10.0.0.10"}, follow_redirects=False)
    assert response.status_code == 409
    assert response.json()["detail"]
    assert client.get(path).json()["host"]["ip"] == "10.0.0.11"


def test_edit_host_accepts_new_ip(client: TestClient) -> None:
    path = _create_host(client, "10.0.0.12")
    response = client.post(f"{path}/edit", data={"ip": "10.0.0.99"}, follow_redirects=False)
    _assert_outcome(response, redirect_to=path)
    assert client.get(path).json()["host"]["ip"] == "10.0.0.99"


def test_hostnames_add_and_hide_return_json(client: TestClient) -> None:
    path = _create_host(client)
    response = client.post(f"{path}/hostnames", data={"name": "  API.Internal  "})
    _assert_outcome(response)
    hostname_id, name = client.get(path).json()["hostnames"][0]
    assert name == "api.internal"
    deleted = client.post(f"{path}/hostnames/{hostname_id}/delete")
    _assert_outcome(deleted)
    assert client.get(path).json()["hostnames"] == []


def test_service_mutations_persist_without_returning_collections(client: TestClient) -> None:
    path = _create_host(client)
    created = client.post(f"{path}/services", data={"port": "443", "service_name": "https"})
    _assert_outcome(created)
    service = client.get(path).json()["services"][0]
    assert service["port"] == 443
    assert service["service_name"] == "https"
    assert service["manual"] is True
    service_id = service["service_id"]
    edited = client.post(ENGAGEMENT_PREFIX + f"/services/{service_id}/edit", data={
        "state": "open", "service_name": "https", "product": "nginx",
        "status": "interesting", "tags": "web, tls",
    })
    _assert_outcome(edited)
    resolved = client.get(path).json()["services"][0]
    assert resolved["product"] == "nginx"
    assert resolved["annotation"]["status"] == "interesting"
    assert resolved["annotation"]["tags"] == ["web", "tls"]
    assert {"id", "host_id", "service_id", "engagement_id"}.isdisjoint(resolved["annotation"])
    persisted = client.get(path).json()["services"][0]["annotation"]
    assert {"id", "host_id", "service_id", "engagement_id"}.isdisjoint(persisted)
    deleted = client.post(ENGAGEMENT_PREFIX + f"/services/{service_id}/delete")
    _assert_outcome(deleted)
    assert client.get(path).json()["services"] == []


def test_notes_and_annotation_round_trip_in_host_context(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    created = client.post(ENGAGEMENT_PREFIX + "/notes", data={"host_id": host_id, "title": "  Recon  ", "body_md": "raw\nbody"})
    _assert_outcome(created)
    note = client.get(path).json()["host_notes"][0]
    assert note["title"] == "Recon"
    assert note["body_md"] == "raw\nbody"
    assert note["updated_at"]
    edited = client.post(ENGAGEMENT_PREFIX + f'/notes/{note["id"]}/edit', data={"title": "Updated", "body_md": "new body"})
    _assert_outcome(edited)
    assert client.get(path).json()["host_notes"][0]["body_md"] == "new body"
    saved = client.post(ENGAGEMENT_PREFIX + "/annotation", data={"host_id": host_id, "status": "interesting", "tags": "pivot, web"})
    _assert_outcome(saved)
    assert client.get(path).json()["host_ann"]["status"] == "interesting"
    annotation = client.get(ENGAGEMENT_PREFIX + "/annotation", params={"host_id": host_id})
    assert annotation.status_code == 200
    assert annotation.json()["ann"]["tags"] == ["pivot", "web"]
    assert {"id", "host_id", "service_id", "engagement_id"}.isdisjoint(annotation.json()["ann"])
    detail = client.get(path).json()
    assert detail["host_notes"][0]["title"] == "Updated"
    assert detail["host_ann"]["status"] == "interesting"
    assert {"id", "host_id", "service_id", "engagement_id"}.isdisjoint(detail["host_ann"])
    deleted = client.post(ENGAGEMENT_PREFIX + f'/notes/{note["id"]}/delete')
    _assert_outcome(deleted)
    assert client.get(path).json()["host_notes"] == []


def test_linked_credentials_serialize_hosts_and_services(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22", service_name="ssh")["service_id"]
    credential_id = _create_credential(client, username="root", secret="toor")["id"]
    linked = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/link/host", data={"host_id": host_id})
    _assert_outcome(linked)
    credential = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]
    assert credential["hosts"][0]["ip"] == "10.0.0.5"
    assert credential["pickable_services"][0]["service_id"] == service_id
    linked_service = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/link/service", data={"service_id": str(service_id)})
    _assert_outcome(linked_service)
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]["services"][0]["name"] == "ssh"
    detail = client.get(path).json()
    assert detail["host_credentials"][0]["id"] == credential_id
    edited = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/edit", data={"host_id": host_id, "username": "admin", "secret": "changed"})
    _assert_outcome(edited)
    assert client.get(path).json()["host_credentials"][0]["username"] == "admin"
    unlinked_service = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/unlink/service/{service_id}")
    _assert_outcome(unlinked_service)
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]["services"] == []
    unlinked_host = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/unlink/host/{host_id}")
    _assert_outcome(unlinked_host)
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]["hosts"] == []
    deleted = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/delete")
    _assert_outcome(deleted)
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"] == []


def test_unlink_host_removes_only_its_credential_service_links(client: TestClient) -> None:
    host_path = _create_host(client)
    other_path = _create_host(client, "10.0.0.6")
    host_id = int(host_path.rsplit("/", 1)[1])
    other_id = int(other_path.rsplit("/", 1)[1])
    service_ids: list[int] = []
    for path, port in ((host_path, 22), (host_path, 443), (other_path, 22)):
        service_ids.append(_create_service(client, path, port=str(port))["service_id"])
    credential_id = _create_credential(client, username="root", secret="toor")["id"]
    other_credential_id = _create_credential(client, username="admin", secret="other")["id"]
    for cid in (credential_id, other_credential_id):
        for hid in (host_id, other_id):
            client.post(ENGAGEMENT_PREFIX + f"/credentials/{cid}/link/host", data={"host_id": str(hid)})
        for sid in service_ids:
            client.post(ENGAGEMENT_PREFIX + f"/credentials/{cid}/link/service", data={"service_id": str(sid)})

    response = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/unlink/host/{host_id}")
    _assert_outcome(response)
    credentials = {credential["id"]: credential for credential in client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"]}
    credential = credentials[credential_id]
    assert [host["host_id"] for host in credential["hosts"]] == [other_id]
    assert [service["service_id"] for service in credential["services"]] == [service_ids[2]]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    other = credentials[other_credential_id]
    assert {host["host_id"] for host in other["hosts"]} == {host_id, other_id}
    assert {service["service_id"] for service in other["services"]} == set(service_ids)

    # Re-linking the host must not resurrect its old service associations.
    client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/unlink/host/{host_id}")
    client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/link/host", data={"host_id": str(host_id)})
    persisted = {credential["id"]: credential for credential in client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"]}
    assert [service["service_id"] for service in persisted[credential_id]["services"]] == [service_ids[2]]


def test_search_serializes_all_result_sources(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    client.post(f"{path}/hostnames", data={"name": "needle.internal"})
    client.post(ENGAGEMENT_PREFIX + "/notes", data={"host_id": host_id, "title": "Needle", "body_md": "needle evidence"})
    client.post(ENGAGEMENT_PREFIX + "/credentials", data={"username": "needle", "secret": "secret"})
    data = client.get(ENGAGEMENT_PREFIX + "/search", params={"q": " needle "}).json()
    assert data["q"] == "needle"
    assert data["results"]["hosts"][0]["ip"] == "10.0.0.5"
    assert data["results"]["notes"][0]["href"] == path
    assert data["results"]["credentials"][0]["username"] == "needle"


@pytest.mark.parametrize("query", [" OPERATOR ", " Private-Marker "])
def test_search_credentials_exclude_secrets_and_management_data(client: TestClient, query: str) -> None:
    path = _create_host(client)
    host_id = int(path.rsplit("/", 1)[1])
    client.post(f"{path}/services", data={"port": "22", "service_name": "ssh"})
    created = _create_credential(client,
        username="operator",
        secret="search-must-not-expose-this",
        notes="private-marker management notes",
        host_ids=[str(host_id)],
    )

    response = client.get(ENGAGEMENT_PREFIX + "/search", params={"q": query})
    assert response.status_code == 200
    assert response.json()["results"]["credentials"] == [{
        "id": created["id"],
        "kind": "password",
        "username": "operator",
        "hosts": [{"host_id": host_id, "ip": "10.0.0.5"}],
    }]
    assert "search-must-not-expose-this" not in response.text
    assert "private-marker management notes" not in response.text
    managed = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]
    assert managed["secret"] == "search-must-not-expose-this"
    assert managed["notes"] == "private-marker management notes"


@pytest.mark.parametrize("fields", [
    {"port": "-1"}, {"port": "65536"}, {"port": "22", "proto": "bogus"},
    {"port": "22", "state": "bogus"},
])
def test_manual_service_rejects_invalid_identity_or_state(client: TestClient, fields: dict[str, str]) -> None:
    path = _create_host(client)
    response = client.post(f"{path}/services", data=fields)
    assert response.status_code == 400
    assert response.json()["field_errors"]
    assert client.get(path).json()["services"] == []


def test_invalid_service_edit_preserves_overrides_and_annotation(client: TestClient) -> None:
    path = _create_host(client)
    service = _create_service(client, path, port="22", version="keep")
    response = client.post(ENGAGEMENT_PREFIX + f"/services/{service['service_id']}/edit", data={
        "state": "bogus", "version": "discard", "status": "exploited",
    })
    assert response.status_code == 400
    current = client.get(path).json()["services"][0]
    assert current["version"] == "keep"
    assert current["annotation"] is None


def test_empty_credential_edit_is_rejected_without_changing_record(client: TestClient) -> None:
    credential = _create_credential(client, username="root")
    response = client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential['id']}/edit", data={
        "username": " ", "secret": " ", "notes": "discard",
    })
    assert response.status_code == 422
    persisted = client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]
    assert persisted["username"] == "root"
    assert persisted["notes"] == ""


def test_credential_service_requires_explicit_host_link(client: TestClient) -> None:
    path = _create_host(client)
    host_id = path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22")["service_id"]
    credential_id = _create_credential(client, username="root")["id"]
    route = ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/link/service"
    assert client.post(route, data={"service_id": str(service_id)}).status_code == 422
    client.post(ENGAGEMENT_PREFIX + f"/credentials/{credential_id}/link/host", data={"host_id": host_id})
    assert client.post(route, data={"service_id": str(service_id)}).status_code == 200
    assert client.post(route, data={"service_id": str(service_id)}).status_code == 200
    assert len(client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]["services"]) == 1


def test_annotation_allows_reclassification(client: TestClient) -> None:
    host_id = _create_host(client).rsplit("/", 1)[1]
    route = ENGAGEMENT_PREFIX + "/annotation"
    _assert_outcome(client.post(route, data={"host_id": host_id, "status": "exploited"}))
    first = client.get(path := ENGAGEMENT_PREFIX + f"/hosts/{host_id}").json()["host_ann"]
    _assert_outcome(client.post(route, data={"host_id": host_id, "status": "new"}))
    second = client.get(path).json()["host_ann"]
    assert first["status"] == "exploited"
    assert second["status"] == "new"


def test_service_override_reset_delete_and_scan_recreation_keep_action_history(client: TestClient) -> None:
    _upload(client, SCAN_A, "baseline.xml")
    path = _create_host(client, "10.0.0.1")
    host_id = path.rsplit("/", 1)[1]
    service = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    service_id = service["service_id"]
    route = ENGAGEMENT_PREFIX + f"/services/{service_id}"
    client.post(route + "/edit", data={"state": "filtered", "version": "override", "status": "interesting", "tags": "keep"})
    credential_id = _create_credential(client,
        username="root", host_ids=[host_id], service_ids=[str(service_id)],
    )["id"]
    _upload(client, SCAN_B, "newer.xml")
    detail = client.get(path).json()
    overridden = next(service for service in detail["services"] if service["port"] == 22)
    assert (overridden["state"], overridden["version"]) == ("filtered", "override")

    reset = client.post(route + "/edit", data={"state": "", "version": "", "status": "interesting", "tags": "keep"})
    _assert_outcome(reset)
    inherited = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    assert (inherited["state"], inherited["version"]) == ("open", "9.0")
    assert inherited["annotation"]["tags"] == ["keep"]
    assert inherited["overrides"]["version"] is None
    assert client.post(route + "/delete").status_code == 200
    removed = client.get(path).json()
    assert 22 not in [service["port"] for service in removed["services"]]
    assert len([entry for entry in removed["host_timeline"]["entries"] if entry["source"] == "manual"]) == 3
    credential = next(credential for credential in client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"] if credential["id"] == credential_id)
    assert credential["services"] == []
    assert len(credential["hosts"]) == 1

    _upload(client, SCAN_B, "rediscovered.xml")
    recreated = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    assert recreated["version"] == "9.0"
    assert recreated["annotation"] is None
    assert all(value is None for value in recreated["overrides"].values())
    entries = client.get(path).json()["host_timeline"]["entries"]
    actions = [entry["changes"][0] for entry in entries if entry["source"] == "manual"]
    assert [action["kind"] for action in actions] == ["removed", "changed", "changed"]
    assert actions[1]["before_overrides"]["version"] == "override"
    assert actions[1]["after_overrides"]["version"] is None


def test_manual_host_commands_reuse_legacy_equivalence_and_guard_collisions(
    client: TestClient, session: Session, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from penrecon.db import get_session
    from penrecon.models import Host, Note
    from penrecon.web.app import app
    from tests.fixtures import TEST_ENGAGEMENT_ID

    legacy = Host(ip="2001:0DB8::0001", engagement_id=TEST_ENGAGEMENT_ID)
    canonical = Host(ip="2001:db8::1", engagement_id=TEST_ENGAGEMENT_ID)
    target = Host(ip="2001:db8::2", engagement_id=TEST_ENGAGEMENT_ID)
    session.add_all([legacy, canonical, target])
    session.flush()
    session.add(Note(host_id=legacy.id, title="Keep", body_md="legacy notes", engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()
    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: session)
    legacy_path = ENGAGEMENT_PREFIX + f"/hosts/{legacy.id}"
    created = client.post(ENGAGEMENT_PREFIX + "/hosts", data={"ip": "2001:db8:0:0::1"}, follow_redirects=False)
    _assert_outcome(created, redirect_to=legacy_path)
    unchanged = client.post(legacy_path + "/edit", data={"ip": "2001:db8::1"}, follow_redirects=False)
    _assert_outcome(unchanged, redirect_to=legacy_path)
    detail = client.get(legacy_path).json()
    assert detail["host"]["ip"] == "2001:0DB8::0001"
    assert detail["host_notes"][0]["body_md"] == "legacy notes"
    rejected = client.post(ENGAGEMENT_PREFIX + f"/hosts/{target.id}/edit", data={"ip": "2001:db8:0:0::1"}, follow_redirects=False)
    assert rejected.status_code == 409
    rows = client.get(ENGAGEMENT_PREFIX + "/").json()["rows"]
    assert {row["ip"] for row in rows} == {"2001:0DB8::0001", "2001:db8::1", "2001:db8::2"}


@pytest.mark.parametrize("action", ["create_host", "edit_host", "delete_host", "scan", "operation"])
def test_document_mutations_redirect_without_following(client: TestClient, action: str) -> None:
    headers = {"Accept": "text/html"}
    if action == "create_host":
        response = client.post(ENGAGEMENT_PREFIX + "/hosts", data={"ip": "10.0.0.8"}, headers=headers, follow_redirects=False)
        destination = response.headers["location"]
        assert client.get(destination).json()["host"]["ip"] == "10.0.0.8"
    elif action in {"edit_host", "delete_host"}:
        path = _create_host(client)
        suffix = "/edit" if action == "edit_host" else "/delete"
        response = client.post(path + suffix, data={"ip": "10.0.0.9"}, headers=headers, follow_redirects=False)
        destination = path if action == "edit_host" else ENGAGEMENT_PREFIX + "/"
        if action == "edit_host":
            assert client.get(path).json()["host"]["ip"] == "10.0.0.9"
        else:
            assert client.get(path).status_code == 404
    elif action == "scan":
        response = client.post(ENGAGEMENT_PREFIX + "/scans", data={"tool": "nmap"},
                               files={"file": ("document.xml", SCAN_A, "text/xml")},
                               headers=headers, follow_redirects=False)
        destination = ENGAGEMENT_PREFIX + "/scans"
        assert client.get(destination).json()["scans"][0]["filename"] == "document.xml"
    else:
        response = client.post(ENGAGEMENT_PREFIX + "/operations", data={"command": "id"},
                               headers=headers, follow_redirects=False)
        destination = ENGAGEMENT_PREFIX + "/operations"
        assert client.get(destination).json()["operations"][0]["command"] == "id"
    assert response.status_code == 303
    assert response.headers["location"] == destination
    assert response.history == []
