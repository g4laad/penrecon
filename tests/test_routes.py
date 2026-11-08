from __future__ import annotations

import json
import re
from urllib.parse import urlencode, parse_qs, urlsplit

import pytest
from starlette.testclient import TestClient
from sqlmodel import Session

from tests.fixtures import SCAN_A, SCAN_B
from tests.fixtures import api_url, TEST_ENGAGEMENT_ID

DOCUMENT_PREFIX = f"/e/{TEST_ENGAGEMENT_ID}"

def _assert_outcome(response, *, redirect_to: str | None = None) -> None:
    assert response.status_code == 200
    assert "location" not in response.headers
    assert response.json() == ({"ok": True, "redirect_to": redirect_to} if redirect_to else {"ok": True})


def _create_service(client: TestClient, path: str, **fields) -> dict:
    _assert_outcome(client.post(api_url(f"{urlsplit(path).path.removeprefix('/api')}/services", parse_qs(urlsplit(path).query)["engagement_id"][0]), data=fields, follow_redirects=False))
    return next(service for service in client.get(path).json()["services"] if service["port"] == int(fields["port"]))


def _create_credential(client: TestClient, **fields) -> dict:
    _assert_outcome(client.post(api_url("/credentials"), data=fields, follow_redirects=False))
    return next(credential for credential in client.get(api_url("/credentials")).json()["credentials"]
                if credential["username"] == fields.get("username", "").strip())


def _credential_details(client: TestClient) -> list[dict]:
    summaries = client.get(api_url("/credentials")).json()["credentials"]
    return [
        client.get(api_url(f'/credentials/{summary["id"]}')).json()["credential"]
        for summary in summaries
    ]



def _create_host(client: TestClient, ip: str = "10.0.0.5") -> str:
    response = client.post(api_url("/hosts"), data={"ip": ip}, follow_redirects=False)
    _assert_outcome(response, redirect_to=response.json()["redirect_to"])
    engagement_id, _, host_id = urlsplit(response.json()["redirect_to"]).path.strip("/").split("/")[1:]
    return api_url(f"/hosts/{host_id}", engagement_id)


def _upload(client: TestClient, content: str, filename: str) -> None:
    response = client.post(
        api_url("/scans"), files={"file": (filename, content, "text/xml")},
        data={"tool": "nmap"}, follow_redirects=False,
    )
    _assert_outcome(response, redirect_to=DOCUMENT_PREFIX + "/scans")


@pytest.mark.parametrize("accept", ["application/json", "text/html", "*/*", ""])
def test_page_shell_embeds_only_safe_bootstrap_and_local_assets(client: TestClient, accept: str) -> None:
    query = '</script><script>alert("x")</script>&>\u2028\u2029tail'
    renamed = client.put(api_url("/engagements"), data={"name": query})
    assert renamed.status_code == 200
    response = client.get(DOCUMENT_PREFIX + "/search", params={"q": query}, headers={"Accept": accept})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "vary" not in response.headers
    assert '<div id="root"></div>' in response.text
    assets = re.findall(r'(?:src|href)="(/static/ui/[^"]+)"', response.text)
    assert len(assets) == 2
    for asset in assets:
        assert client.get(asset).status_code == 200
    match = re.search(r'<script id="page-data" type="application/json">(.*?)</script>', response.text)
    assert match is not None
    embedded = match.group(1)
    assert json.loads(embedded)["engagement"]["id"] == TEST_ENGAGEMENT_ID
    assert json.loads(embedded)["engagement"]["name"] == query
    assert set(json.loads(embedded)) == {"engagement", "engagements"}
    assert query not in response.text
    assert client.get(api_url("/search" + "?" + urlencode({"q": query}))).json()["q"] == query


@pytest.mark.parametrize(
    ("path", "key"),
    [(api_url("/hosts"), "rows"), (api_url("/search"), "results"), (api_url("/credentials"), "credentials"),
     (api_url("/scans"), "scans"), (api_url("/diff"), "result"), (api_url("/operations"), "operations")],
)
def test_page_json_contexts(client: TestClient, path: str, key: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "vary" not in response.headers
    data = response.json()
    assert key in data
    assert "engagement" not in data
    assert "engagements" not in data
    assert "request" not in data
    html_accept = client.get(path, headers={"Accept": "text/html"})
    assert html_accept.status_code == 200
    assert html_accept.headers["content-type"].startswith("application/json")
    assert html_accept.json() == data


def test_missing_host_404(client: TestClient) -> None:
    response = client.get(api_url("/hosts/999999"))
    assert response.status_code == 404
    assert response.json()["detail"] == "host not found"


def test_create_host_redirects_to_detail(client: TestClient) -> None:
    path = _create_host(client)
    assert urlsplit(path).path.startswith("/api/hosts/")
    assert parse_qs(urlsplit(path).query) == {"engagement_id": [TEST_ENGAGEMENT_ID]}
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
    response = client.post(api_url("/hosts"), data={"ip": "not-an-ip"}, follow_redirects=False)
    assert response.status_code == 400
    assert set(response.json()["field_errors"]) == {"ip"}


def test_delete_host_redirects_home(client: TestClient) -> None:
    path = _create_host(client, "10.0.0.6")
    response = client.delete(path, follow_redirects=False)
    _assert_outcome(response, redirect_to=DOCUMENT_PREFIX + "/")
    assert client.get(path).status_code == 404


def test_export_csv_headers(client: TestClient) -> None:
    response = client.get(api_url("/export/hosts.csv"))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]


def test_create_credential_lists_it(client: TestClient) -> None:
    response = client.post(
        api_url("/credentials"), data={"kind": "password", "username": "root", "secret": "toor"},
    )
    _assert_outcome(response)
    credential = _credential_details(client)[0]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    assert credential["kind"] == "password"


def test_create_credential_with_multiple_targets_deduplicates_links(client: TestClient) -> None:
    paths = [_create_host(client), _create_host(client, "10.0.0.6")]
    host_ids = [int(urlsplit(path).path.rsplit("/", 1)[1]) for path in paths]
    service_ids = [
        _create_service(client, path, port="22")["service_id"]
        for path in paths
    ]
    response = client.post(api_url("/credentials"), data={
        "username": " root ", "secret": " toor ", "notes": " shared ",
        "host_ids": [str(hid) for hid in [*host_ids, host_ids[0]]],
        "service_ids": [str(sid) for sid in [*service_ids, service_ids[0]]],
    })
    _assert_outcome(response)
    credential = _credential_details(client)[0]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    assert credential["notes"] == "shared"
    assert credential["kind"] == "password"
    assert sorted(host["host_id"] for host in credential["hosts"]) == sorted(host_ids)
    assert sorted(service["service_id"] for service in credential["services"]) == sorted(service_ids)
    persisted = _credential_details(client)
    assert persisted == [credential]
    for path in paths:
        assert client.get(path).json()["host_credentials"][0]["id"] == credential["id"]


@pytest.mark.parametrize("invalid_target", ["unknown_host", "unknown_service", "unselected_host", "no_hosts"])
def test_create_credential_rejects_invalid_targets_without_partial_writes(
    client: TestClient, invalid_target: str,
) -> None:
    path = _create_host(client)
    other_path = _create_host(client, "10.0.0.6")
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22")["service_id"]
    other_service_id = _create_service(client, other_path, port="443")["service_id"]
    _create_credential(client, username="existing")
    existing = client.get(api_url("/credentials")).json()["credentials"]
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
    response = client.post(api_url("/credentials"), data=data)
    assert response.status_code == 422
    assert client.get(api_url("/credentials")).json()["credentials"] == existing
    assert client.get(path).json()["host_credentials"] == []
    assert client.get(other_path).json()["host_credentials"] == []


@pytest.mark.parametrize("data", [{}, {"username": "  ", "secret": "\t", "notes": "notes only"}])
def test_create_credential_rejects_empty_identity(client: TestClient, data: dict[str, str]) -> None:
    response = client.post(api_url("/credentials"), data=data)
    assert response.status_code == 422
    assert client.get(api_url("/credentials")).json()["credentials"] == []




def test_upload_scan_then_host_appears(client: TestClient) -> None:
    _upload(client, SCAN_A, "a.xml")
    row = client.get(api_url("/hosts")).json()["rows"][0]
    assert row["ip"] == "10.0.0.1"
    assert row["hostnames"] == ["a.example"]
    assert row["open_services"] == [[22, "ssh"], [80, "http"]]
    detail = client.get(api_url(f'/hosts/{row["id"]}')).json()
    assert [service["port"] for service in detail["services"]] == [22, 80]
    assert detail["services"][0]["version"] == "8.9"
    assert detail["hostnames"][0][1] == "a.example"
    scan = client.get(api_url("/scans")).json()["scans"][0]
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
    client.post(api_url(f"{urlsplit(other_path).path.removeprefix('/api')}/services", parse_qs(urlsplit(other_path).query)["engagement_id"][0]), data={"port": "443", "service_name": "https"})

    data = client.get(api_url("/hosts" + "?" + urlencode(params))).json()
    assert [row["ip"] for row in data["rows"]] == expected_ips
    assert {"per", "per_page"}.isdisjoint(data)
    for row in data["rows"]:
        assert {"open_ports", "service_names"}.isdisjoint(row)


def test_diff_serializes_scans_and_changes(client: TestClient) -> None:
    _upload(client, SCAN_A, "a.xml")
    _upload(client, SCAN_B, "b.xml")
    scans = client.get(api_url("/scans")).json()["scans"]
    ids = {scan["filename"]: scan["id"] for scan in scans}
    data = client.get(api_url("/diff" + "?" + urlencode({"a": ids["a.xml"], "b": ids["b.xml"]}))).json()
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
    response = client.patch(path, data={"ip": "10.0.0.10"}, follow_redirects=False)
    assert response.status_code == 409
    assert response.json()["detail"]
    assert client.get(path).json()["host"]["ip"] == "10.0.0.11"


def test_edit_host_accepts_new_ip(client: TestClient) -> None:
    path = _create_host(client, "10.0.0.12")
    response = client.patch(path, data={"ip": "10.0.0.99"}, follow_redirects=False)
    _assert_outcome(response, redirect_to=DOCUMENT_PREFIX + urlsplit(path).path.removeprefix("/api"))
    assert client.get(path).json()["host"]["ip"] == "10.0.0.99"


def test_hostnames_add_and_hide_return_json(client: TestClient) -> None:
    path = _create_host(client)
    response = client.post(api_url(f"{urlsplit(path).path.removeprefix('/api')}/hostnames", parse_qs(urlsplit(path).query)["engagement_id"][0]), data={"name": "  API.Internal  "})
    _assert_outcome(response)
    hostname_id, name = client.get(path).json()["hostnames"][0]
    assert name == "api.internal"
    deleted = client.delete(api_url(f"{urlsplit(path).path.removeprefix('/api')}/hostnames/{hostname_id}", parse_qs(urlsplit(path).query)["engagement_id"][0]))
    _assert_outcome(deleted)
    assert client.get(path).json()["hostnames"] == []


def test_service_mutations_persist_without_returning_collections(client: TestClient) -> None:
    path = _create_host(client)
    created = client.post(api_url(f"{urlsplit(path).path.removeprefix('/api')}/services", parse_qs(urlsplit(path).query)["engagement_id"][0]), data={"port": "443", "service_name": "https"})
    _assert_outcome(created)
    service = client.get(path).json()["services"][0]
    assert service["port"] == 443
    assert service["service_name"] == "https"
    assert service["manual"] is True
    service_id = service["service_id"]
    edited = client.put(api_url(f"/services/{service_id}"), data={
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
    deleted = client.delete(api_url(f"/services/{service_id}"))
    _assert_outcome(deleted)
    assert client.get(path).json()["services"] == []


def test_notes_and_annotation_round_trip_in_host_context(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    created = client.post(api_url("/notes"), data={"host_id": host_id, "title": "  Recon  ", "body_md": "raw\nbody"})
    _assert_outcome(created)
    note = client.get(path).json()["host_notes"][0]
    assert note["title"] == "Recon"
    assert note["body_md"] == "raw\nbody"
    assert note["updated_at"]
    edited = client.put(api_url(f'/notes/{note["id"]}'), data={"title": "Updated", "body_md": "new body"})
    _assert_outcome(edited)
    assert client.get(path).json()["host_notes"][0]["body_md"] == "new body"
    saved = client.put(api_url("/annotation"), data={"host_id": host_id, "status": "interesting", "tags": "pivot, web"})
    _assert_outcome(saved)
    assert client.get(path).json()["host_ann"]["status"] == "interesting"
    annotation = client.get(api_url("/annotation" + "?" + urlencode({"host_id": host_id})))
    assert annotation.status_code == 200
    assert annotation.json()["ann"]["tags"] == ["pivot", "web"]
    assert {"id", "host_id", "service_id", "engagement_id"}.isdisjoint(annotation.json()["ann"])
    detail = client.get(path).json()
    assert detail["host_notes"][0]["title"] == "Updated"
    assert detail["host_ann"]["status"] == "interesting"
    assert {"id", "host_id", "service_id", "engagement_id"}.isdisjoint(detail["host_ann"])
    deleted = client.delete(api_url(f'/notes/{note["id"]}'))
    _assert_outcome(deleted)
    assert client.get(path).json()["host_notes"] == []


def test_linked_credentials_serialize_hosts_and_services(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22", service_name="ssh")["service_id"]
    credential_id = _create_credential(client, username="root", secret="toor")["id"]
    linked = client.patch(api_url(f"/credentials/{credential_id}/hosts"), data={"host_id": host_id})
    _assert_outcome(linked)
    credential = _credential_details(client)[0]
    assert credential["hosts"][0]["ip"] == "10.0.0.5"
    options = client.get(api_url(f"/credentials/{credential_id}/options/services")).json()
    assert options["services"][0]["service_id"] == service_id
    linked_service = client.patch(api_url(f"/credentials/{credential_id}/services"), data={"service_id": str(service_id)})
    _assert_outcome(linked_service)
    assert _credential_details(client)[0]["services"][0]["name"] == "ssh"
    detail = client.get(path).json()
    assert detail["host_credentials"][0]["id"] == credential_id
    edited = client.put(api_url(f"/credentials/{credential_id}"), data={"username": "admin", "secret": "changed"})
    _assert_outcome(edited)
    assert client.get(path).json()["host_credentials"][0]["username"] == "admin"
    unlinked_service = client.delete(api_url(f"/credentials/{credential_id}/services/{service_id}"))
    _assert_outcome(unlinked_service)
    assert _credential_details(client)[0]["services"] == []
    unlinked_host = client.delete(api_url(f"/credentials/{credential_id}/hosts/{host_id}"))
    _assert_outcome(unlinked_host)
    assert _credential_details(client)[0]["hosts"] == []
    deleted = client.delete(api_url(f"/credentials/{credential_id}"))
    _assert_outcome(deleted)
    assert client.get(api_url("/credentials")).json()["credentials"] == []


def test_unlink_host_removes_only_its_credential_service_links(client: TestClient) -> None:
    host_path = _create_host(client)
    other_path = _create_host(client, "10.0.0.6")
    host_id = int(urlsplit(host_path).path.rsplit("/", 1)[1])
    other_id = int(urlsplit(other_path).path.rsplit("/", 1)[1])
    service_ids: list[int] = []
    for path, port in ((host_path, 22), (host_path, 443), (other_path, 22)):
        service_ids.append(_create_service(client, path, port=str(port))["service_id"])
    credential_id = _create_credential(client, username="root", secret="toor")["id"]
    other_credential_id = _create_credential(client, username="admin", secret="other")["id"]
    for cid in (credential_id, other_credential_id):
        for hid in (host_id, other_id):
            client.patch(api_url(f"/credentials/{cid}/hosts"), data={"host_id": str(hid)})
        for sid in service_ids:
            client.patch(api_url(f"/credentials/{cid}/services"), data={"service_id": str(sid)})

    response = client.delete(api_url(f"/credentials/{credential_id}/hosts/{host_id}"))
    _assert_outcome(response)
    credentials = {credential["id"]: credential for credential in _credential_details(client)}
    credential = credentials[credential_id]
    assert [host["host_id"] for host in credential["hosts"]] == [other_id]
    assert [service["service_id"] for service in credential["services"]] == [service_ids[2]]
    assert credential["username"] == "root"
    assert credential["secret"] == "toor"
    other = credentials[other_credential_id]
    assert {host["host_id"] for host in other["hosts"]} == {host_id, other_id}
    assert {service["service_id"] for service in other["services"]} == set(service_ids)

    # Re-linking the host must not resurrect its old service associations.
    client.delete(api_url(f"/credentials/{credential_id}/hosts/{host_id}"))
    client.patch(api_url(f"/credentials/{credential_id}/hosts"), data={"host_id": str(host_id)})
    persisted = {credential["id"]: credential for credential in _credential_details(client)}
    assert [service["service_id"] for service in persisted[credential_id]["services"]] == [service_ids[2]]


def test_search_serializes_all_result_sources(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    client.post(api_url(f"{urlsplit(path).path.removeprefix('/api')}/hostnames", parse_qs(urlsplit(path).query)["engagement_id"][0]), data={"name": "needle.internal"})
    client.post(api_url("/notes"), data={"host_id": host_id, "title": "Needle", "body_md": "needle evidence"})
    client.post(api_url("/credentials"), data={"username": "needle", "secret": "secret"})
    data = client.get(api_url("/search" + "?" + urlencode({"q": " needle "}))).json()
    assert data["q"] == "needle"
    assert data["results"]["hosts"][0]["ip"] == "10.0.0.5"
    assert data["results"]["notes"][0]["href"] == DOCUMENT_PREFIX + urlsplit(path).path.removeprefix("/api")
    assert data["results"]["credentials"][0]["username"] == "needle"


@pytest.mark.parametrize("query", [" OPERATOR ", " Private-Marker "])
def test_search_credentials_exclude_secrets_and_management_data(client: TestClient, query: str) -> None:
    path = _create_host(client)
    host_id = int(urlsplit(path).path.rsplit("/", 1)[1])
    client.post(api_url(f"{urlsplit(path).path.removeprefix('/api')}/services", parse_qs(urlsplit(path).query)["engagement_id"][0]), data={"port": "22", "service_name": "ssh"})
    created = _create_credential(client,
        username="operator",
        secret="search-must-not-expose-this",
        notes="private-marker management notes",
        host_ids=[str(host_id)],
    )

    response = client.get(api_url("/search" + "?" + urlencode({"q": query})))
    assert response.status_code == 200
    assert response.json()["results"]["credentials"] == [{
        "id": created["id"],
        "kind": "password",
        "username": "operator",
        "hosts": [{"host_id": host_id, "ip": "10.0.0.5"}],
    }]
    assert "search-must-not-expose-this" not in response.text
    assert "private-marker management notes" not in response.text
    managed = _credential_details(client)[0]
    assert managed["secret"] == "search-must-not-expose-this"
    assert managed["notes"] == "private-marker management notes"


@pytest.mark.parametrize("fields", [
    {"port": "-1"}, {"port": "65536"}, {"port": "22", "proto": "bogus"},
    {"port": "22", "state": "bogus"},
])
def test_manual_service_rejects_invalid_identity_or_state(client: TestClient, fields: dict[str, str]) -> None:
    path = _create_host(client)
    response = client.post(api_url(f"{urlsplit(path).path.removeprefix('/api')}/services", parse_qs(urlsplit(path).query)["engagement_id"][0]), data=fields)
    assert response.status_code == 400
    assert response.json()["field_errors"]
    assert client.get(path).json()["services"] == []


def test_invalid_service_edit_preserves_overrides_and_annotation(client: TestClient) -> None:
    path = _create_host(client)
    service = _create_service(client, path, port="22", version="keep")
    response = client.put(api_url(f"/services/{service['service_id']}"), data={
        "state": "bogus", "version": "discard", "status": "exploited",
    })
    assert response.status_code == 400
    current = client.get(path).json()["services"][0]
    assert current["version"] == "keep"
    assert current["annotation"] is None


def test_empty_credential_edit_is_rejected_without_changing_record(client: TestClient) -> None:
    credential = _create_credential(client, username="root")
    response = client.put(api_url(f"/credentials/{credential['id']}"), data={
        "username": " ", "secret": " ", "notes": "discard",
    })
    assert response.status_code == 422
    persisted = _credential_details(client)[0]
    assert persisted["username"] == "root"
    assert persisted["notes"] == ""


def test_credential_service_requires_explicit_host_link(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22")["service_id"]
    credential_id = _create_credential(client, username="root")["id"]
    route = api_url(f"/credentials/{credential_id}/services")
    assert client.patch(route, data={"service_id": str(service_id)}).status_code == 422
    client.patch(api_url(f"/credentials/{credential_id}/hosts"), data={"host_id": host_id})
    assert client.patch(route, data={"service_id": str(service_id)}).status_code == 200
    assert client.patch(route, data={"service_id": str(service_id)}).status_code == 200
    assert len(_credential_details(client)[0]["services"]) == 1


def test_annotation_allows_reclassification(client: TestClient) -> None:
    host_id = urlsplit(_create_host(client)).path.rsplit("/", 1)[1]
    route = api_url("/annotation")
    _assert_outcome(client.put(route, data={"host_id": host_id, "status": "exploited"}))
    first = client.get(path := api_url(f"/hosts/{host_id}")).json()["host_ann"]
    _assert_outcome(client.put(route, data={"host_id": host_id, "status": "new"}))
    second = client.get(path).json()["host_ann"]
    assert first["status"] == "exploited"
    assert second["status"] == "new"


def test_service_override_reset_delete_and_scan_recreation_keep_action_history(client: TestClient) -> None:
    _upload(client, SCAN_A, "baseline.xml")
    path = _create_host(client, "10.0.0.1")
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    service = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    service_id = service["service_id"]
    route = api_url(f"/services/{service_id}")
    client.put(route, data={"state": "filtered", "version": "override", "status": "interesting", "tags": "keep"})
    credential_id = _create_credential(client,
        username="root", host_ids=[host_id], service_ids=[str(service_id)],
    )["id"]
    _upload(client, SCAN_B, "newer.xml")
    detail = client.get(path).json()
    overridden = next(service for service in detail["services"] if service["port"] == 22)
    assert (overridden["state"], overridden["version"]) == ("filtered", "override")

    reset = client.put(route, data={"state": "", "version": "", "status": "interesting", "tags": "keep"})
    _assert_outcome(reset)
    inherited = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    assert (inherited["state"], inherited["version"]) == ("open", "9.0")
    assert inherited["annotation"]["tags"] == ["keep"]
    assert inherited["overrides"]["version"] is None
    assert client.delete(route).status_code == 200
    removed = client.get(path).json()
    assert 22 not in [service["port"] for service in removed["services"]]
    assert len([entry for entry in removed["host_timeline"]["entries"] if entry["source"] == "manual"]) == 3
    credential = next(credential for credential in _credential_details(client) if credential["id"] == credential_id)
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
    legacy_path = api_url(f"/hosts/{legacy.id}")
    created = client.post(api_url("/hosts"), data={"ip": "2001:db8:0:0::1"}, follow_redirects=False)
    _assert_outcome(created, redirect_to=DOCUMENT_PREFIX + urlsplit(legacy_path).path.removeprefix("/api"))
    unchanged = client.patch(legacy_path, data={"ip": "2001:db8::1"}, follow_redirects=False)
    _assert_outcome(unchanged, redirect_to=DOCUMENT_PREFIX + urlsplit(legacy_path).path.removeprefix("/api"))
    detail = client.get(legacy_path).json()
    assert detail["host"]["ip"] == "2001:0DB8::0001"
    assert detail["host_notes"][0]["body_md"] == "legacy notes"
    rejected = client.patch(api_url(f"/hosts/{target.id}"), data={"ip": "2001:db8:0:0::1"}, follow_redirects=False)
    assert rejected.status_code == 409
    rows = client.get(api_url("/hosts")).json()["rows"]
    assert {row["ip"] for row in rows} == {"2001:0DB8::0001", "2001:db8::1", "2001:db8::2"}


@pytest.mark.parametrize("action", ["create_host", "edit_host", "delete_host", "scan", "operation"])
def test_api_mutations_return_json_even_when_html_is_requested(client: TestClient, action: str) -> None:
    headers = {"Accept": "text/html"}
    if action == "create_host":
        response = client.post(api_url("/hosts"), data={"ip": "10.0.0.8"}, headers=headers)
        destination = response.json()["redirect_to"]
        assert destination.startswith(DOCUMENT_PREFIX + "/hosts/")
        assert client.get(api_url("/" + urlsplit(destination).path.strip("/").split("/", 2)[2], urlsplit(destination).path.strip("/").split("/")[1])).json()["host"]["ip"] == "10.0.0.8"
    elif action in {"edit_host", "delete_host"}:
        path = _create_host(client)
        method = "PATCH" if action == "edit_host" else "DELETE"
        response = client.request(method, path, data={"ip": "10.0.0.9"}, headers=headers)
        destination = DOCUMENT_PREFIX + urlsplit(path).path.removeprefix("/api") if action == "edit_host" else DOCUMENT_PREFIX + "/"
        if action == "edit_host":
            assert client.get(path).json()["host"]["ip"] == "10.0.0.9"
        else:
            assert client.get(path).status_code == 404
    elif action == "scan":
        response = client.post(api_url("/scans"), data={"tool": "nmap"},
                               files={"file": ("document.xml", SCAN_A, "text/xml")}, headers=headers)
        destination = DOCUMENT_PREFIX + "/scans"
        assert client.get(api_url("/" + urlsplit(destination).path.strip("/").split("/", 2)[2], urlsplit(destination).path.strip("/").split("/")[1])).json()["scans"][0]["filename"] == "document.xml"
    else:
        response = client.post(api_url("/operations"), data={"command": "id"}, headers=headers)
        destination = DOCUMENT_PREFIX + "/operations"
        assert client.get(api_url("/" + urlsplit(destination).path.strip("/").split("/", 2)[2], urlsplit(destination).path.strip("/").split("/")[1])).json()["operations"][0]["command"] == "id"
    _assert_outcome(response, redirect_to=destination)
    assert response.headers["content-type"].startswith("application/json")
    assert response.history == []


def test_patch_host_renames_only_ip_and_blank_is_noop(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="443", service_name="https")["service_id"]
    _assert_outcome(client.put(api_url(f"/services/{service_id}"), data={
        "service_name": "custom-https", "status": "interesting", "tags": "service-triage",
    }))
    _assert_outcome(client.post(api_url("/notes"), data={
        "host_id": host_id, "title": "Keep note", "body_md": "preserved evidence",
    }))
    _assert_outcome(client.put(api_url("/annotation"), data={
        "host_id": host_id, "status": "exploited", "tags": "host-triage",
    }))
    _create_credential(client, username="operator", host_ids=[host_id], service_ids=[str(service_id)])
    before = client.get(path).json()

    _assert_outcome(client.patch(path, data={"ip": "10.0.0.99"}),
                    redirect_to=DOCUMENT_PREFIX + f"/hosts/{host_id}")
    renamed = client.get(path).json()
    assert renamed["host"] == {**before["host"], "ip": "10.0.0.99"}
    for key in ("services", "host_notes", "host_ann", "host_credentials", "hostnames", "host_timeline"):
        assert renamed[key] == before[key]

    _assert_outcome(client.patch(path, data={"ip": "  "}),
                    redirect_to=DOCUMENT_PREFIX + f"/hosts/{host_id}")
    assert client.get(path).json() == renamed
    assert client.patch(path, data={}).status_code == 422
    assert client.get(path).json() == renamed


def test_put_service_omitted_fields_reset_overrides_and_triage(client: TestClient) -> None:
    _upload(client, SCAN_A, "baseline.xml")
    path = _create_host(client, "10.0.0.1")
    service_id = next(service for service in client.get(path).json()["services"]
                      if service["port"] == 22)["service_id"]
    endpoint = api_url(f"/services/{service_id}")
    _assert_outcome(client.put(endpoint, data={
        "state": "filtered", "service_name": "custom", "product": "override",
        "version": "manual-version", "status": "exploited", "tags": "reset-me",
    }))

    _assert_outcome(client.put(endpoint, data={"version": "replacement"}))
    service = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    assert (service["state"], service["service_name"], service["product"], service["version"]) == (
        "open", "ssh", "OpenSSH", "replacement",
    )
    assert service["overrides"] == {
        "state": None, "service_name": None, "product": None, "version": "replacement",
    }
    assert service["annotation"]["status"] == "new"
    assert service["annotation"]["tags"] == []

    _assert_outcome(client.put(endpoint, data={}))
    service = next(service for service in client.get(path).json()["services"] if service["port"] == 22)
    assert service["version"] == "8.9"
    assert all(value is None for value in service["overrides"].values())


def test_put_note_and_annotation_reset_omitted_fields(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    _assert_outcome(client.post(api_url("/notes"), data={
        "host_id": host_id, "title": "Original", "body_md": "original evidence",
    }))
    note_id = client.get(path).json()["host_notes"][0]["id"]
    _assert_outcome(client.put(api_url(f"/notes/{note_id}"), data={"title": "Replacement"}))
    note = client.get(path).json()["host_notes"][0]
    assert (note["title"], note["body_md"]) == ("Replacement", "")
    _assert_outcome(client.put(api_url(f"/notes/{note_id}"), data={"body_md": "new evidence"}))
    note = client.get(path).json()["host_notes"][0]
    assert (note["title"], note["body_md"]) == ("Untitled", "new evidence")

    _assert_outcome(client.put(api_url("/annotation"), data={
        "host_id": host_id, "status": "interesting", "tags": "old-tag",
    }))
    _assert_outcome(client.put(api_url("/annotation"), data={"host_id": host_id}))
    annotation = client.get(path).json()["host_ann"]
    assert (annotation["status"], annotation["tags"]) == ("new", [])


def test_put_credential_replaces_scalars_but_keeps_associations(client: TestClient) -> None:
    path = _create_host(client)
    host_id = urlsplit(path).path.rsplit("/", 1)[1]
    service_id = _create_service(client, path, port="22")["service_id"]
    credential = _create_credential(client, kind="token", username="original", secret="old-secret",
                                    notes="old-notes", host_ids=[host_id], service_ids=[str(service_id)])
    endpoint = api_url(f'/credentials/{credential["id"]}')
    before = client.get(endpoint).json()["credential"]
    _assert_outcome(client.put(endpoint, data={"username": "replacement"}))
    after = client.get(endpoint).json()["credential"]
    assert (after["kind"], after["username"], after["secret"], after["notes"]) == (
        "password", "replacement", "", "",
    )
    assert after["hosts"] == before["hosts"]
    assert after["services"] == before["services"]


def test_patch_credential_associations_add_without_replacing_existing_links(client: TestClient) -> None:
    paths = [_create_host(client), _create_host(client, "10.0.0.6")]
    host_ids = [int(urlsplit(path).path.rsplit("/", 1)[1]) for path in paths]
    service_ids = [_create_service(client, path, port="22")["service_id"] for path in paths]
    credential = _create_credential(client, username="operator", secret="keep-secret", notes="keep-notes",
                                    host_ids=[str(host_ids[0])], service_ids=[str(service_ids[0])])
    endpoint = api_url(f'/credentials/{credential["id"]}')
    _assert_outcome(client.patch(api_url(f'/credentials/{credential["id"]}/hosts'),
                                 data={"host_id": str(host_ids[1])}))
    linked_host = client.get(endpoint).json()["credential"]
    assert {host["host_id"] for host in linked_host["hosts"]} == set(host_ids)
    assert [service["service_id"] for service in linked_host["services"]] == [service_ids[0]]
    _assert_outcome(client.patch(api_url(f'/credentials/{credential["id"]}/services'),
                                 data={"service_id": str(service_ids[1])}))
    linked_service = client.get(endpoint).json()["credential"]
    assert {host["host_id"] for host in linked_service["hosts"]} == set(host_ids)
    assert {service["service_id"] for service in linked_service["services"]} == set(service_ids)
    assert (linked_service["username"], linked_service["secret"], linked_service["notes"]) == (
        "operator", "keep-secret", "keep-notes",
    )
