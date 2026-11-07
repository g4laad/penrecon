from __future__ import annotations

import json
import re
from typing import Any

import pytest
from httpx2 import Response
from starlette.testclient import TestClient

from tests.fixtures import ENGAGEMENT_PREFIX, SCAN_A, TEST_ENGAGEMENT_ID


def _host(client: TestClient, ip: str, prefix: str = ENGAGEMENT_PREFIX) -> tuple[str, int]:
    response = client.post(prefix + "/hosts", data={"ip": ip})
    assert response.status_code == 200
    path = response.json()["redirect_to"]
    return path, int(path.rsplit("/", 1)[1])


def _engagement(client: TestClient) -> str:
    response = client.post("/engagements", data={"name": "Other", "description": "private scope metadata"})
    assert response.status_code == 200
    return response.json()["redirect_to"].rstrip("/")


def _embedded(response: Response) -> dict[str, Any]:
    assert response.status_code == 200
    match = re.search(r'<script id="page-data" type="application/json">(.*?)</script>', response.text)
    assert match is not None
    return json.loads(match.group(1))


def test_bootstrap_is_slim_and_catalog_is_separate(client: TestClient) -> None:
    other = _engagement(client)
    data = client.get(ENGAGEMENT_PREFIX + "/bootstrap").json()
    assert set(data) == {"engagement", "engagements"}
    assert data["engagement"] == {"id": TEST_ENGAGEMENT_ID, "name": "Test engagement"}
    assert {entry["id"] for entry in data["engagements"]} == {TEST_ENGAGEMENT_ID, other.rsplit("/", 1)[1]}
    assert all(set(entry) == {"id", "name"} for entry in data["engagements"])
    catalog = client.get("/engagements", params={"sort": "name", "dir": "asc"}).json()
    assert set(catalog) == {"catalog", "sort", "direction"}
    assert [entry["name"] for entry in catalog["catalog"]] == ["Other", "Test engagement"]
    assert catalog["catalog"][0]["description"] == "private scope metadata"
    html = _embedded(client.get("/engagements", headers={"Accept": "text/html"}))
    assert all(set(entry) == {"id", "name"} for entry in html["engagements"])
    assert any(entry["description"] == "private scope metadata" for entry in html["catalog"])


def test_inventory_data_filters_sorts_and_paginates_without_shell(client: TestClient) -> None:
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        _host(client, ip)
    _host(client, "10.0.0.99", _engagement(client))
    params = {"q": "10.0.0.", "sort": "ip", "dir": "desc", "page": "2", "fit": "2"}
    data = client.get(ENGAGEMENT_PREFIX + "/data/hosts", params=params).json()
    assert set(data) == {"rows", "total", "matched", "page", "pages", "q", "port", "tag", "status", "change", "sort", "direction"}
    assert [row["ip"] for row in data["rows"]] == ["10.0.0.1"]
    assert (data["total"], data["matched"], data["page"], data["pages"]) == (3, 3, 2, 2)
    assert (data["q"], data["sort"], data["direction"]) == ("10.0.0.", "ip", "desc")
    filtered = client.get(ENGAGEMENT_PREFIX + "/data/hosts", params={"q": "10.0.0.2", "page": "99"}).json()
    assert [row["ip"] for row in filtered["rows"]] == ["10.0.0.2"]
    assert (filtered["matched"], filtered["page"], filtered["pages"]) == (1, 1, 1)


def test_inventory_html_defers_rows_but_preserves_query_and_shell(client: TestClient) -> None:
    _host(client, "10.0.0.1")
    data = _embedded(client.get(ENGAGEMENT_PREFIX + "/?q=needle&fit=3&page=2", headers={"Accept": "text/html"}))
    assert not {"rows", "total", "matched", "pages"} & data.keys()
    assert (data["q"], data["page"]) == ("needle", 2)
    assert data["engagement"]["id"] == TEST_ENGAGEMENT_ID
    assert client.get(ENGAGEMENT_PREFIX + "/").json()["rows"][0]["ip"] == "10.0.0.1"


def test_service_data_is_only_filtered_paginated_table_state(client: TestClient) -> None:
    path, host_id = _host(client, "10.0.0.1")
    for port in range(100, 112):
        assert client.post(path + "/services", data={"port": port, "service_name": "private-http", "product": "sensitive evidence"}).status_code == 200
    assert client.post(path + "/services", data={"port": 22, "service_name": "ssh"}).status_code == 200
    assert client.post(ENGAGEMENT_PREFIX + "/notes", data={"host_id": host_id, "title": "private note", "body_md": "not table data"}).status_code == 200
    params = {"f_service": "http", "f_state": "open", "sort": "port", "dir": "desc", "per": "10", "page": "2"}
    data = client.get(ENGAGEMENT_PREFIX + f"/data/hosts/{host_id}/services", params=params).json()
    assert set(data) == {"services", "svc_total", "page", "pages", "sort", "direction", "per", "f_port", "f_state", "f_service", "f_status"}
    assert [service["port"] for service in data["services"]] == [101, 100]
    assert (data["svc_total"], data["page"], data["pages"]) == (12, 2, 2)
    assert (data["f_service"], data["f_state"], data["direction"], data["per"]) == ("http", "open", "desc", "10")
    page = client.get(path, params=params).json()
    assert page["host"]["id"] == host_id
    assert page["host_notes"][0]["title"] == "private note"
    assert not {"engagement", "engagements"} & page.keys()


def test_timeline_data_paginates_independently_and_includes_unchanged_on_request(client: TestClient) -> None:
    for filename in ("first.xml", "unchanged.xml"):
        response = client.post(ENGAGEMENT_PREFIX + "/scans", files={"file": (filename, SCAN_A, "text/xml")}, data={"tool": "nmap"})
        assert response.status_code == 200
    host_id = client.get(ENGAGEMENT_PREFIX + "/options/hosts").json()["hosts"][0]["id"]
    path = ENGAGEMENT_PREFIX + f"/hosts/{host_id}"
    for port in range(1000, 1021):
        assert client.post(path + "/services", data={"port": port}).status_code == 200
    endpoint = ENGAGEMENT_PREFIX + f"/data/hosts/{host_id}/timeline"
    data = client.get(endpoint, params={"timeline_page": 2}).json()
    assert set(data) == {"host_timeline"}
    timeline = data["host_timeline"]
    assert (timeline["page"], timeline["pages"], timeline["total"]) == (2, 2, 22)
    assert len(timeline["entries"]) == 2
    assert timeline["show_unchanged"] is False
    expanded = client.get(endpoint, params={"timeline_page": 2, "timeline_unchanged": "true"}).json()["host_timeline"]
    assert expanded["show_unchanged"] is True
    assert expanded["total"] == 23
    assert len(expanded["entries"]) == 3


def test_selector_options_are_minimal_and_credentials_page_has_no_host_catalog(client: TestClient) -> None:
    path, host_id = _host(client, "10.0.0.1")
    _host(client, "10.0.0.2", _engagement(client))
    assert client.post(path + "/services", data={"port": 443, "service_name": "https", "product": "private product", "version": "secret version"}).status_code == 200
    assert client.post(ENGAGEMENT_PREFIX + "/credentials", data={"username": "private", "secret": "secret", "host_ids": [str(host_id)]}).status_code == 200
    assert client.get(ENGAGEMENT_PREFIX + "/options/hosts").json() == {"hosts": [{"id": host_id, "ip": "10.0.0.1"}]}
    service_id = client.get(path).json()["services"][0]["service_id"]
    assert client.get(ENGAGEMENT_PREFIX + f"/options/hosts/{host_id}/services").json() == {
        "services": [{"service_id": service_id, "port": 443, "proto": "tcp", "service_name": "https"}],
    }
    assert set(client.get(ENGAGEMENT_PREFIX + "/credentials").json()) == {"credentials", "total", "kinds", "q", "kind", "scope"}
    empty_path, empty_id = _host(client, "10.0.0.3")
    assert client.get(empty_path).status_code == 200
    assert client.get(ENGAGEMENT_PREFIX + f"/options/hosts/{empty_id}/services").json() == {"services": []}


def test_operation_data_filters_and_paginates_without_other_sections(client: TestClient) -> None:
    for index in range(12):
        assert client.post(ENGAGEMENT_PREFIX + "/operations", data={"command": f"audit-{index}", "output": "operation evidence"}).status_code == 200
    assert client.post(ENGAGEMENT_PREFIX + "/operations", data={"command": "unrelated"}).status_code == 200
    other = _engagement(client)
    assert client.post(other + "/operations", data={"command": "audit-foreign"}).status_code == 200
    params = {"q": "audit", "page": 2, "per": "10"}
    data = client.get(ENGAGEMENT_PREFIX + "/data/operations", params=params).json()
    assert set(data) == {"operations", "total", "q", "page", "pages", "per"}
    assert (data["total"], data["page"], data["pages"], data["q"], data["per"]) == (12, 2, 2, "audit", "10")
    assert len(data["operations"]) == 2
    assert all(operation["command"].startswith("audit-") and operation["command"] != "audit-foreign" for operation in data["operations"])
    assert all(set(operation) == {"id", "started_at", "destination", "tool", "command"} for operation in data["operations"])


def test_credential_lists_are_summaries_in_json_and_html_and_detail_refreshes(client: TestClient) -> None:
    path, host_id = _host(client, "10.0.0.1")
    assert client.post(path + "/services", data={"port": 22, "service_name": "ssh"}).status_code == 200
    service_id = client.get(path).json()["services"][0]["service_id"]
    notes = "long credential notes " * 10000 + "buried-note-needle"
    assert client.post(ENGAGEMENT_PREFIX + "/credentials", data={
        "username": "operator", "secret": "private-secret-marker", "notes": notes,
        "host_ids": [str(host_id)],
    }).status_code == 200
    data = client.get(ENGAGEMENT_PREFIX + "/credentials").json()
    summary = data["credentials"][0]
    assert set(summary) == {"id", "kind", "username", "notes_preview", "host_count", "service_count"}
    assert summary["notes_preview"] == notes[:160]
    assert (summary["host_count"], summary["service_count"], data["total"]) == (1, 0, 1)
    assert (data["q"], data["kind"], data["scope"]) == ("", "", "")
    html = client.get(ENGAGEMENT_PREFIX + "/credentials", headers={"Accept": "text/html"})
    assert _embedded(html)["credentials"] == [summary]
    assert "private-secret-marker" not in html.text
    assert "buried-note-needle" not in html.text
    filtered = client.get(ENGAGEMENT_PREFIX + "/credentials", params={
        "filter": "buried-note-needle", "kind": "password", "scope": "linked",
    }).json()
    assert filtered["credentials"] == [summary]
    assert (filtered["q"], filtered["kind"], filtered["scope"]) == ("buried-note-needle", "password", "linked")
    assert client.get(ENGAGEMENT_PREFIX + "/credentials", params={"scope": "unknown"}).json()["credentials"] == []
    assert client.get(ENGAGEMENT_PREFIX + "/credentials", params={"filter": "10.0.0.1"}).json()["credentials"] == [summary]
    assert client.get(ENGAGEMENT_PREFIX + "/credentials", params={"filter": "ssh"}).json()["credentials"] == []
    endpoint = ENGAGEMENT_PREFIX + f'/credentials/{summary["id"]}'
    response = client.get(endpoint, headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    detail = response.json()["credential"]
    assert detail["secret"] == "private-secret-marker"
    assert detail["notes"] == notes
    assert [service["service_id"] for service in detail["pickable_services"]] == [service_id]
    assert {"engagement_id", "attachment_path"}.isdisjoint(detail)
    assert client.post(endpoint + "/edit", data={
        "username": "updated", "secret": "changed-secret", "notes": "changed notes",
    }).status_code == 200
    assert client.post(endpoint + "/link/service", data={"service_id": service_id}).status_code == 200
    refreshed = client.get(endpoint).json()["credential"]
    assert (refreshed["username"], refreshed["secret"], refreshed["notes"]) == ("updated", "changed-secret", "changed notes")
    assert [service["service_id"] for service in refreshed["services"]] == [service_id]
    assert refreshed["pickable_services"] == []
    assert client.get(ENGAGEMENT_PREFIX + "/credentials").json()["credentials"][0]["service_count"] == 1
    assert client.post(endpoint + f"/unlink/host/{host_id}").status_code == 200
    refreshed = client.get(endpoint).json()["credential"]
    assert refreshed["hosts"] == refreshed["services"] == refreshed["pickable_services"] == []


@pytest.mark.parametrize("field", ["output", "comments", "description", "source", "user_context"])
def test_operation_lists_search_full_details_but_return_only_summaries(client: TestClient, field: str) -> None:
    body = "large private evidence " * 10000 + "buried-operation-needle"
    assert client.post(ENGAGEMENT_PREFIX + "/operations", data={"command": "inspect", field: body}).status_code == 200
    data = client.get(ENGAGEMENT_PREFIX + "/operations", params={"q": "buried-operation-needle"}).json()
    assert data["total"] == 1
    summary = data["operations"][0]
    assert set(summary) == {"id", "started_at", "destination", "tool", "command"}
    assert "buried-operation-needle" not in json.dumps(summary)
    html = client.get(ENGAGEMENT_PREFIX + "/operations", headers={"Accept": "text/html"})
    assert _embedded(html)["operations"] == [summary]
    assert "buried-operation-needle" not in html.text
    endpoint = ENGAGEMENT_PREFIX + f'/operations/{summary["id"]}'
    response = client.get(endpoint, headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    detail = response.json()["operation"]
    assert detail[field] == body
    assert {"engagement_id", "attachment_path", "attachment_media_type"}.isdisjoint(detail)
    assert client.post(endpoint + "/edit", data={"command": "updated", "output": "new evidence"}).status_code == 200
    refreshed = client.get(endpoint).json()["operation"]
    assert (refreshed["command"], refreshed["output"]) == ("updated", "new evidence")
    assert client.get(ENGAGEMENT_PREFIX + "/operations", params={"q": "buried-operation-needle"}).json()["operations"] == []


@pytest.mark.parametrize("resource", ["credentials", "operations"])
def test_detail_resources_reject_missing_and_foreign_ids(client: TestClient, resource: str) -> None:
    other = _engagement(client)
    fields = {"username": "foreign", "secret": "foreign-secret"} if resource == "credentials" else {"command": "foreign", "output": "foreign evidence"}
    assert client.post(other + "/" + resource, data=fields).status_code == 200
    foreign_id = client.get(other + "/" + resource).json()[resource][0]["id"]
    for resource_id in (foreign_id, 999999):
        response = client.get(ENGAGEMENT_PREFIX + f"/{resource}/{resource_id}")
        assert response.status_code == 404
        assert "foreign" not in response.text
    assert client.get("/e/missing/" + resource + f"/{foreign_id}").status_code == 404


@pytest.mark.parametrize("resource", ["data/hosts/{host_id}/services", "data/hosts/{host_id}/timeline", "options/hosts/{host_id}/services"])
def test_host_resources_reject_missing_and_foreign_hosts(client: TestClient, resource: str) -> None:
    _, foreign_id = _host(client, "10.0.0.1", _engagement(client))
    for host_id in (foreign_id, 999999):
        response = client.get(ENGAGEMENT_PREFIX + "/" + resource.format(host_id=host_id))
        assert response.status_code == 404
        assert response.json() == {"detail": "host not found"}


@pytest.mark.parametrize("resource", ["bootstrap", "data/hosts", "data/hosts/1/services", "data/hosts/1/timeline", "data/operations", "options/hosts", "options/hosts/1/services"])
def test_scoped_resources_reject_missing_engagement(client: TestClient, resource: str) -> None:
    response = client.get("/e/missing/" + resource)
    assert response.status_code == 404
    assert response.json() == {"detail": "engagement not found"}
