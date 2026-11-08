from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode, urlsplit

import pytest
from httpx2 import Response
from starlette.testclient import TestClient

from tests.fixtures import SCAN_A, TEST_ENGAGEMENT_ID, api_url


def _host(
    client: TestClient, ip: str, engagement_id: str = TEST_ENGAGEMENT_ID
) -> tuple[str, int]:
    response = client.post(api_url("/hosts", engagement_id), data={"ip": ip})
    assert response.status_code == 200
    document_path = urlsplit(response.json()["redirect_to"]).path
    host_id = int(document_path.rsplit("/", 1)[1])
    assert document_path == f"/{engagement_id}/hosts/{host_id}"
    return api_url(f"/hosts/{host_id}", engagement_id), host_id


def _engagement(client: TestClient) -> str:
    response = client.post(
        "/api/engagements",
        data={"name": "Other", "description": "private scope metadata"},
    )
    assert response.status_code == 200
    return urlsplit(response.json()["redirect_to"]).path.strip("/")


def _embedded(response: Response) -> dict[str, Any]:
    assert response.status_code == 200
    match = re.search(
        r'<script id="page-data" type="application/json">(.*?)</script>', response.text
    )
    assert match is not None
    return json.loads(match.group(1))


def test_bootstrap_is_slim_and_catalog_is_separate(client: TestClient) -> None:
    other = _engagement(client)
    data = _embedded(client.get(f"/{TEST_ENGAGEMENT_ID}/"))
    assert set(data) == {"engagement", "engagements"}
    assert data["engagement"] == {"id": TEST_ENGAGEMENT_ID, "name": "Test engagement"}
    assert {entry["id"] for entry in data["engagements"]} == {TEST_ENGAGEMENT_ID, other}
    assert all(set(entry) == {"id", "name"} for entry in data["engagements"])
    catalog = client.get(
        "/api/engagements", params={"sort": "name", "dir": "asc"}
    ).json()
    assert set(catalog) == {"catalog", "sort", "direction"}
    assert [entry["name"] for entry in catalog["catalog"]] == [
        "Other",
        "Test engagement",
    ]
    assert catalog["catalog"][0]["description"] == "private scope metadata"
    html = _embedded(client.get("/engagements", headers={"Accept": "text/html"}))
    assert set(html) == {"engagement", "engagements"}
    assert all(set(entry) == {"id", "name"} for entry in html["engagements"])
    assert "private scope metadata" not in json.dumps(html)


def test_inventory_data_filters_sorts_and_paginates_without_shell(
    client: TestClient,
) -> None:
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        _host(client, ip)
    _host(client, "10.0.0.99", _engagement(client))
    params = {"q": "10.0.0.", "sort": "ip", "dir": "desc", "page": "2", "fit": "2"}
    data = client.get(api_url("/hosts?" + urlencode(params))).json()
    assert set(data) == {
        "rows",
        "total",
        "matched",
        "page",
        "pages",
        "q",
        "port",
        "tag",
        "status",
        "change",
        "sort",
        "direction",
        "statuses",
    }
    assert data["statuses"] == ["new", "reviewed", "interesting", "exploited"]
    assert [row["ip"] for row in data["rows"]] == ["10.0.0.1"]
    assert (data["total"], data["matched"], data["page"], data["pages"]) == (3, 3, 2, 2)
    assert (data["q"], data["sort"], data["direction"]) == ("10.0.0.", "ip", "desc")
    filtered = client.get(
        api_url("/hosts?" + urlencode({"q": "10.0.0.2", "page": "99"}))
    ).json()
    assert [row["ip"] for row in filtered["rows"]] == ["10.0.0.2"]
    assert (filtered["matched"], filtered["page"], filtered["pages"]) == (1, 1, 1)


def test_inventory_html_contains_only_navigation_bootstrap(client: TestClient) -> None:
    _host(client, "10.0.0.1")
    data = _embedded(client.get(f"/{TEST_ENGAGEMENT_ID}/?q=needle&fit=3&page=2"))
    assert set(data) == {"engagement", "engagements"}
    assert data["engagement"]["id"] == TEST_ENGAGEMENT_ID
    assert client.get(api_url("/hosts")).json()["rows"][0]["ip"] == "10.0.0.1"


def test_service_data_is_only_filtered_paginated_table_state(
    client: TestClient,
) -> None:
    _, host_id = _host(client, "10.0.0.1")
    for port in range(100, 112):
        assert (
            client.post(
                api_url(f"/hosts/{host_id}/services"),
                data={
                    "port": port,
                    "service_name": "private-http",
                    "product": "sensitive evidence",
                },
            ).status_code
            == 200
        )
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/services"),
            data={"port": 22, "service_name": "ssh"},
        ).status_code
        == 200
    )
    assert (
        client.post(
            api_url("/notes"),
            data={
                "host_id": host_id,
                "title": "private note",
                "body_md": "not table data",
            },
        ).status_code
        == 200
    )
    params = {
        "f_service": "http",
        "f_state": "open",
        "sort": "port",
        "dir": "desc",
        "per": "10",
        "page": "2",
    }
    data = client.get(api_url(f"/hosts/{host_id}/services?" + urlencode(params))).json()
    assert set(data) == {
        "services",
        "svc_total",
        "page",
        "pages",
        "sort",
        "direction",
        "per",
        "f_port",
        "f_state",
        "f_service",
        "f_status",
    }
    assert [service["port"] for service in data["services"]] == [101, 100]
    assert (data["svc_total"], data["page"], data["pages"]) == (12, 2, 2)
    assert (data["f_service"], data["f_state"], data["direction"], data["per"]) == (
        "http",
        "open",
        "desc",
        "10",
    )
    page = client.get(api_url(f"/hosts/{host_id}?" + urlencode(params))).json()
    assert page["host"]["id"] == host_id
    assert page["host_notes"][0]["title"] == "private note"
    assert not {"engagement", "engagements"} & page.keys()


def test_timeline_data_paginates_independently_and_includes_unchanged_on_request(
    client: TestClient,
) -> None:
    for filename in ("first.xml", "unchanged.xml"):
        response = client.post(
            api_url("/scans"),
            files={"file": (filename, SCAN_A, "text/xml")},
            data={"tool": "nmap"},
        )
        assert response.status_code == 200
    host_id = client.get(api_url("/options/hosts")).json()["hosts"][0]["id"]
    for port in range(1000, 1021):
        assert (
            client.post(
                api_url(f"/hosts/{host_id}/services"), data={"port": port}
            ).status_code
            == 200
        )
    endpoint = f"/hosts/{host_id}/timeline"
    data = client.get(api_url(endpoint + "?timeline_page=2")).json()
    assert set(data) == {"host_timeline"}
    timeline = data["host_timeline"]
    assert (timeline["page"], timeline["pages"], timeline["total"]) == (2, 2, 22)
    assert len(timeline["entries"]) == 2
    assert timeline["show_unchanged"] is False
    expanded = client.get(
        api_url(endpoint + "?timeline_page=2&timeline_unchanged=true")
    ).json()["host_timeline"]
    assert expanded["show_unchanged"] is True
    assert expanded["total"] == 23
    assert len(expanded["entries"]) == 3


def test_selector_options_are_minimal_and_credentials_page_has_no_host_catalog(
    client: TestClient,
) -> None:
    path, host_id = _host(client, "10.0.0.1")
    _host(client, "10.0.0.2", _engagement(client))
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/services"),
            data={
                "port": 443,
                "service_name": "https",
                "product": "private product",
                "version": "secret version",
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            api_url("/credentials"),
            data={
                "username": "private",
                "secret": "secret",
                "host_ids": [str(host_id)],
            },
        ).status_code
        == 200
    )
    assert client.get(api_url("/options/hosts")).json() == {
        "hosts": [{"id": host_id, "ip": "10.0.0.1"}]
    }
    service_id = client.get(path).json()["services"][0]["service_id"]
    assert client.get(api_url(f"/options/hosts/{host_id}/services")).json() == {
        "services": [
            {
                "service_id": service_id,
                "port": 443,
                "proto": "tcp",
                "service_name": "https",
            }
        ],
    }
    assert set(client.get(api_url("/credentials")).json()) == {
        "credentials",
        "total",
        "matched",
        "page",
        "pages",
        "per",
        "kinds",
        "q",
        "kind",
        "scope",
    }
    empty_path, empty_id = _host(client, "10.0.0.3")
    assert client.get(empty_path).status_code == 200
    assert client.get(api_url(f"/options/hosts/{empty_id}/services")).json() == {
        "services": []
    }


def test_operation_data_filters_and_paginates_without_other_sections(
    client: TestClient,
) -> None:
    for index in range(12):
        assert (
            client.post(
                api_url("/operations"),
                data={"command": f"audit-{index}", "output": "operation evidence"},
            ).status_code
            == 200
        )
    assert (
        client.post(api_url("/operations"), data={"command": "unrelated"}).status_code
        == 200
    )
    other = _engagement(client)
    assert (
        client.post(
            api_url("/operations", other), data={"command": "audit-foreign"}
        ).status_code
        == 200
    )
    params = {"q": "audit", "page": 2, "per": "10"}
    data = client.get(api_url("/operations?" + urlencode(params))).json()
    assert set(data) == {"operations", "total", "q", "page", "pages", "per"}
    assert (data["total"], data["page"], data["pages"], data["q"], data["per"]) == (
        12,
        2,
        2,
        "audit",
        "10",
    )
    assert len(data["operations"]) == 2
    assert all(
        operation["command"].startswith("audit-")
        and operation["command"] != "audit-foreign"
        for operation in data["operations"]
    )
    assert all(
        set(operation) == {"id", "started_at", "destination", "tool", "command"}
        for operation in data["operations"]
    )


def test_credential_lists_are_summaries_in_json_and_html_and_detail_refreshes(
    client: TestClient,
) -> None:
    path, host_id = _host(client, "10.0.0.1")
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/services"),
            data={"port": 22, "service_name": "ssh"},
        ).status_code
        == 200
    )
    service_id = client.get(path).json()["services"][0]["service_id"]
    notes = "long credential notes " * 10000 + "buried-note-needle"
    assert (
        client.post(
            api_url("/credentials"),
            data={
                "username": "operator",
                "secret": "private-secret-marker",
                "notes": notes,
                "host_ids": [str(host_id)],
            },
        ).status_code
        == 200
    )
    data = client.get(api_url("/credentials")).json()
    summary = data["credentials"][0]
    assert set(summary) == {
        "id",
        "kind",
        "username",
        "notes_preview",
        "host_count",
        "service_count",
    }
    assert summary["notes_preview"] == notes[:160]
    assert (summary["host_count"], summary["service_count"], data["total"]) == (1, 0, 1)
    html = client.get(f"/{TEST_ENGAGEMENT_ID}/credentials")
    assert set(_embedded(html)) == {"engagement", "engagements"}
    assert "private-secret-marker" not in html.text
    assert "buried-note-needle" not in html.text
    filtered = client.get(
        api_url(
            "/credentials?"
            + urlencode(
                {
                    "filter": "buried-note-needle",
                    "kind": "password",
                    "scope": "linked",
                }
            )
        )
    ).json()
    assert filtered["credentials"] == [summary]
    assert (filtered["q"], filtered["kind"], filtered["scope"]) == (
        "buried-note-needle",
        "password",
        "linked",
    )
    assert client.get(api_url("/credentials?scope=unknown")).json()["credentials"] == []
    assert client.get(api_url("/credentials?filter=10.0.0.1")).json()[
        "credentials"
    ] == [summary]
    assert client.get(api_url("/credentials?filter=ssh")).json()["credentials"] == []
    endpoint = api_url(f"/credentials/{summary['id']}")
    response = client.get(endpoint, headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    detail = response.json()["credential"]
    assert detail["secret"] == "private-secret-marker"
    assert detail["notes"] == notes
    options_endpoint = api_url(f"/credentials/{summary['id']}/options/services")
    options = client.get(options_endpoint)
    assert options.headers["cache-control"] == "no-store"
    assert [service["service_id"] for service in options.json()["services"]] == [
        service_id
    ]
    assert "pickable_services" not in detail
    assert {"engagement_id", "attachment_path"}.isdisjoint(detail)
    assert (
        client.put(
            api_url(f"/credentials/{summary['id']}"),
            data={
                "username": "updated",
                "secret": "changed-secret",
                "notes": "changed notes",
            },
        ).status_code
        == 200
    )
    assert (
        client.patch(
            api_url(f"/credentials/{summary['id']}/services"),
            data={"service_id": service_id},
        ).status_code
        == 200
    )
    refreshed = client.get(endpoint).json()["credential"]
    assert (refreshed["username"], refreshed["secret"], refreshed["notes"]) == (
        "updated",
        "changed-secret",
        "changed notes",
    )
    assert [service["service_id"] for service in refreshed["services"]] == [service_id]
    assert client.get(options_endpoint).json()["services"] == []
    assert (
        client.get(api_url("/credentials")).json()["credentials"][0]["service_count"]
        == 1
    )
    assert (
        client.delete(
            api_url(f"/credentials/{summary['id']}/hosts/{host_id}")
        ).status_code
        == 200
    )
    refreshed = client.get(endpoint).json()["credential"]
    assert refreshed["hosts"] == refreshed["services"] == []
    assert client.get(options_endpoint).json()["services"] == []


@pytest.mark.parametrize(
    "field", ["output", "comments", "description", "source", "user_context"]
)
def test_operation_lists_search_full_details_but_return_only_summaries(
    client: TestClient, field: str
) -> None:
    body = "large private evidence " * 10000 + "buried-operation-needle"
    assert (
        client.post(
            api_url("/operations"), data={"command": "inspect", field: body}
        ).status_code
        == 200
    )
    data = client.get(api_url("/operations?q=buried-operation-needle")).json()
    assert data["total"] == 1
    summary = data["operations"][0]
    assert set(summary) == {"id", "started_at", "destination", "tool", "command"}
    assert "buried-operation-needle" not in json.dumps(summary)
    html = client.get(f"/{TEST_ENGAGEMENT_ID}/operations")
    assert set(_embedded(html)) == {"engagement", "engagements"}
    assert "buried-operation-needle" not in html.text
    endpoint = api_url(f"/operations/{summary['id']}")
    response = client.get(endpoint, headers={"Accept": "text/html"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    detail = response.json()["operation"]
    assert detail[field] == body
    assert {"engagement_id", "attachment_path", "attachment_media_type"}.isdisjoint(
        detail
    )
    assert (
        client.put(
            api_url(f"/operations/{summary['id']}"),
            data={"command": "updated", "output": "new evidence"},
        ).status_code
        == 200
    )
    refreshed = client.get(endpoint).json()["operation"]
    assert (refreshed["command"], refreshed["output"]) == ("updated", "new evidence")
    assert (
        client.get(api_url("/operations?q=buried-operation-needle")).json()[
            "operations"
        ]
        == []
    )


@pytest.mark.parametrize("resource", ["credentials", "operations"])
def test_detail_resources_reject_missing_and_foreign_ids(
    client: TestClient, resource: str
) -> None:
    other = _engagement(client)
    fields = (
        {"username": "foreign", "secret": "foreign-secret"}
        if resource == "credentials"
        else {"command": "foreign", "output": "foreign evidence"}
    )
    assert client.post(api_url("/" + resource, other), data=fields).status_code == 200
    foreign_id = client.get(api_url("/" + resource, other)).json()[resource][0]["id"]
    for resource_id in (foreign_id, 999999):
        response = client.get(api_url(f"/{resource}/{resource_id}"))
        assert response.status_code == 404
        assert "foreign" not in response.text
    assert (
        client.get(api_url(f"/{resource}/{foreign_id}", "missing")).status_code == 404
    )


@pytest.mark.parametrize(
    "resource",
    [
        "hosts/{host_id}/services",
        "hosts/{host_id}/timeline",
        "options/hosts/{host_id}/services",
    ],
)
def test_host_resources_reject_missing_and_foreign_hosts(
    client: TestClient, resource: str
) -> None:
    _, foreign_id = _host(client, "10.0.0.1", _engagement(client))
    for host_id in (foreign_id, 999999):
        response = client.get(api_url("/" + resource.format(host_id=host_id)))
        assert response.status_code == 404
        assert response.json() == {"detail": "host not found"}


@pytest.mark.parametrize(
    "resource",
    [
        "hosts",
        "hosts/1/services",
        "hosts/1/timeline",
        "operations",
        "credentials",
        "search",
        "scans",
        "options/hosts",
        "options/hosts/1/services",
    ],
)
@pytest.mark.parametrize("engagement_id,status", [(None, 422), ("missing", 404)])
def test_scoped_resources_require_existing_engagement(
    client: TestClient,
    resource: str,
    engagement_id: str | None,
    status: int,
) -> None:
    endpoint = (
        "/api/" + resource
        if engagement_id is None
        else api_url("/" + resource, engagement_id)
    )
    response = client.get(endpoint)
    assert response.status_code == status
    assert isinstance(response.json()["detail"], str)
    if status == 404:
        assert response.json() == {"detail": "engagement not found"}


def test_query_selects_engagement_independently_for_each_request(
    client: TestClient,
) -> None:
    other = _engagement(client)
    _, first_host_id = _host(client, "10.0.0.1")
    _, second_host_id = _host(client, "10.0.0.2", other)
    for engagement_id, expected_ip, own_host_id, foreign_host_id in (
        (TEST_ENGAGEMENT_ID, "10.0.0.1", first_host_id, second_host_id),
        (other, "10.0.0.2", second_host_id, first_host_id),
        (TEST_ENGAGEMENT_ID, "10.0.0.1", first_host_id, second_host_id),
    ):
        inventory = client.get(api_url("/hosts", engagement_id))
        assert inventory.status_code == 200
        assert [row["ip"] for row in inventory.json()["rows"]] == [expected_ip]
        assert (
            client.get(api_url(f"/hosts/{own_host_id}", engagement_id)).status_code
            == 200
        )
        assert (
            client.get(api_url(f"/hosts/{foreign_host_id}", engagement_id)).status_code
            == 404
        )


def test_mutation_query_scope_cannot_be_overridden_by_form_body(
    client: TestClient,
) -> None:
    other = _engagement(client)
    response = client.post(
        api_url("/hosts"),
        data={"ip": "10.0.0.8", "engagement_id": other},
    )
    assert response.status_code == 200
    assert response.json()["redirect_to"].startswith(f"/{TEST_ENGAGEMENT_ID}/hosts/")
    assert [row["ip"] for row in client.get(api_url("/hosts")).json()["rows"]] == [
        "10.0.0.8"
    ]
    assert client.get(api_url("/hosts", other)).json()["rows"] == []
    edited = client.put(
        api_url("/engagements", other),
        data={"name": "Renamed other", "engagement_id": TEST_ENGAGEMENT_ID},
    )
    assert edited.status_code == 200
    names = {
        entry["id"]: entry["name"]
        for entry in client.get("/api/engagements").json()["catalog"]
    }
    assert names[other] == "Renamed other"
    assert names[TEST_ENGAGEMENT_ID] == "Test engagement"


@pytest.mark.parametrize("engagement_id,status", [(None, 422), ("missing", 404)])
def test_valid_form_scope_does_not_replace_missing_or_unknown_query(
    client: TestClient,
    engagement_id: str | None,
    status: int,
) -> None:
    endpoint = (
        "/api/hosts" if engagement_id is None else api_url("/hosts", engagement_id)
    )
    response = client.post(
        endpoint,
        data={"ip": "10.0.0.8", "engagement_id": TEST_ENGAGEMENT_ID},
    )
    assert response.status_code == status
    assert isinstance(response.json()["detail"], str)
    assert client.get(api_url("/hosts")).json()["rows"] == []


def test_put_engagement_replaces_description_when_omitted(client: TestClient) -> None:
    assert (
        client.put(
            api_url("/engagements"),
            data={
                "name": "Original",
                "description": "Reset this description",
            },
        ).status_code
        == 200
    )
    response = client.put(api_url("/engagements"), data={"name": "Replacement"})
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    engagement = client.get("/api/engagements").json()["catalog"][0]
    assert (engagement["name"], engagement["description"]) == ("Replacement", "")


def test_put_operation_replaces_entire_editable_form_and_keeps_attachment(
    client: TestClient,
) -> None:
    assert (
        client.post(
            api_url("/operations"),
            data={
                "started_at": "2026-01-01T12:00",
                "ended_at": "2026-01-01T12:05",
                "source": "operator",
                "destination": "10.0.0.1",
                "tool": "shell",
                "user_context": "root",
                "command": "original",
                "output": "old output",
                "description": "old description",
                "comments": "old comments",
                "tags": "old-tag",
            },
            files={"attachment": ("evidence.txt", b"keep evidence", "text/plain")},
        ).status_code
        == 200
    )
    operation_id = client.get(api_url("/operations")).json()["operations"][0]["id"]
    endpoint = api_url(f"/operations/{operation_id}")
    response = client.put(endpoint, data={"command": "replacement"})
    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "redirect_to": f"/{TEST_ENGAGEMENT_ID}/operations",
    }
    operation = client.get(endpoint).json()["operation"]
    assert operation["command"] == "replacement"
    assert operation["started_at"] is operation["ended_at"] is None
    for field in (
        "source",
        "destination",
        "tool",
        "user_context",
        "output",
        "description",
        "comments",
    ):
        assert operation[field] == ""
    assert operation["tags"] == []
    attachment = client.get(api_url(f"/operations/{operation_id}/attachment"))
    assert attachment.status_code == 200
    assert attachment.content == b"keep evidence"


@pytest.mark.parametrize(
    "resource",
    [
        "host",
        "hostname",
        "service",
        "note",
        "credential",
        "credential_host",
        "credential_service",
        "operation",
    ],
)
def test_delete_removes_only_resource_in_query_scope(
    client: TestClient, resource: str
) -> None:
    other = _engagement(client)
    host_path, host_id = _host(client, "10.0.0.1")
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/hostnames"), data={"name": "owned.example"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/services"), data={"port": "22"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            api_url("/notes"), data={"host_id": host_id, "title": "Owned note"}
        ).status_code
        == 200
    )
    service_id = client.get(host_path).json()["services"][0]["service_id"]
    assert (
        client.post(
            api_url("/credentials"),
            data={
                "username": "owned",
                "host_ids": [str(host_id)],
                "service_ids": [str(service_id)],
            },
        ).status_code
        == 200
    )
    assert (
        client.post(api_url("/operations"), data={"command": "owned"}).status_code
        == 200
    )
    credential_id = client.get(api_url("/credentials")).json()["credentials"][0]["id"]
    operation_id = client.get(api_url("/operations")).json()["operations"][0]["id"]
    credential_path = api_url(f"/credentials/{credential_id}")
    operation_path = api_url(f"/operations/{operation_id}")
    before = client.get(host_path).json()
    credential = client.get(credential_path).json()
    operation = client.get(operation_path).json()
    endpoints = {
        "host": f"/hosts/{host_id}",
        "hostname": f"/hosts/{host_id}/hostnames/{before['hostnames'][0][0]}",
        "service": f"/services/{service_id}",
        "note": f"/notes/{before['host_notes'][0]['id']}",
        "credential": f"/credentials/{credential_id}",
        "credential_host": f"/credentials/{credential_id}/hosts/{host_id}",
        "credential_service": f"/credentials/{credential_id}/services/{service_id}",
        "operation": f"/operations/{operation_id}",
    }
    response = client.request(
        "DELETE",
        api_url(endpoints[resource], other),
        data={"engagement_id": TEST_ENGAGEMENT_ID, "host_id": host_id},
    )
    assert response.status_code == 404
    assert client.get(host_path).json() == before
    assert client.get(credential_path).json() == credential
    assert client.get(operation_path).json() == operation
    response = client.request(
        "DELETE",
        api_url(endpoints[resource]),
        data={"engagement_id": other, "host_id": host_id},
    )
    assert response.status_code == 200
    assert response.json()["ok"] is True
    if resource == "host":
        assert client.get(host_path).status_code == 404
        assert client.get(credential_path).json()["credential"]["hosts"] == []
    elif resource in {"hostname", "service", "note"}:
        key = {"hostname": "hostnames", "service": "services", "note": "host_notes"}[
            resource
        ]
        assert client.get(host_path).json()[key] == []
    elif resource == "credential":
        assert client.get(credential_path).status_code == 404
        assert client.get(host_path).json()["host_credentials"] == []
    elif resource in {"credential_host", "credential_service"}:
        remaining = client.get(credential_path).json()["credential"]
        assert remaining["services"] == []
        assert len(remaining["hosts"]) == (0 if resource == "credential_host" else 1)
    else:
        assert client.get(operation_path).status_code == 404
        assert client.get(api_url("/operations")).json()["operations"] == []
    assert client.get(api_url("/hosts", other)).json()["rows"] == []
    assert client.get(api_url("/credentials", other)).json()["credentials"] == []
    assert client.get(api_url("/operations", other)).json()["operations"] == []
