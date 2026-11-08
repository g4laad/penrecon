from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from jsonschema import Draft202012Validator
from starlette.testclient import TestClient

from tests.fixtures import SCAN_A, TEST_ENGAGEMENT_ID, api_url


@pytest.mark.parametrize(
    "origin",
    [
        "http://attacker.example",
        "http://testserver.attacker.example",
        "https://testserver",
        "http://testserver:81",
        "http://localhost",
        "null",
    ],
)
def test_cross_origin_mutation_is_rejected_without_writing(
    client: TestClient, origin: str
) -> None:
    response = client.post(
        api_url("/hosts"), data={"ip": "10.0.0.8"}, headers={"Origin": origin}
    )
    assert response.status_code == 403
    assert isinstance(response.json()["detail"], str)
    assert client.get(api_url("/hosts")).json()["rows"] == []


def test_mutation_requires_request_header_without_writing(client: TestClient) -> None:
    client.headers.pop("X-Penrecon-Request")
    response = client.post(api_url("/hosts"), data={"ip": "10.0.0.8"})
    assert response.status_code == 403
    assert isinstance(response.json()["detail"], str)
    assert client.get(api_url("/hosts")).json()["rows"] == []


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]", "testserver"])
def test_same_origin_loopback_mutation_is_allowed(
    client: TestClient, host: str
) -> None:
    response = client.post(
        api_url("/hosts"),
        data={"ip": "10.0.0.8"},
        headers={
            "Host": host,
            "Origin": "http://" + host,
            "Sec-Fetch-Site": "same-origin",
        },
    )
    assert response.status_code == 200
    assert client.get(api_url("/hosts")).json()["rows"][0]["ip"] == "10.0.0.8"


@pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete"])
def test_cross_site_fetch_is_rejected_for_all_api_methods(
    client: TestClient, method: str
) -> None:
    path = api_url("/hosts")
    kwargs = {"data": {"ip": "10.0.0.8"}} if method != "get" else {}
    response = client.request(
        method, path, headers={"Sec-Fetch-Site": "cross-site"}, **kwargs
    )
    assert response.status_code == 403
    assert isinstance(response.json()["detail"], str)
    assert client.get(api_url("/hosts")).json()["rows"] == []


@pytest.mark.parametrize(
    "host", ["attacker.example", "localhost.attacker.example", "127.0.0.2"]
)
def test_untrusted_host_cannot_write(client: TestClient, host: str) -> None:
    response = client.post(
        api_url("/hosts"), data={"ip": "10.0.0.8"}, headers={"Host": host}
    )
    assert response.status_code == 400
    assert isinstance(response.json()["detail"], str)
    assert client.get(api_url("/hosts")).json()["rows"] == []


@pytest.mark.parametrize(
    "method,path,fields,headers,status",
    [
        ("get", api_url("/hosts"), None, {}, 200),
        ("post", api_url("/hosts"), {"ip": "10.0.0.8"}, {}, 200),
        ("get", api_url("/hosts/999999"), None, {}, 404),
        ("get", "/api/unknown", None, {}, 404),
        ("post", api_url("/hosts"), {}, {}, 422),
        (
            "post",
            api_url("/hosts"),
            {"ip": "10.0.0.8"},
            {"Origin": "http://attacker.example"},
            403,
        ),
    ],
)
def test_api_json_and_security_headers_do_not_depend_on_accept(
    client: TestClient,
    method: str,
    path: str,
    fields: dict[str, str] | None,
    headers: dict[str, str],
    status: int,
) -> None:
    kwargs = {"data": fields} if fields is not None else {}
    response = getattr(client, method)(
        path, headers={"Accept": "text/html", **headers}, **kwargs
    )
    assert response.status_code == status
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "vary" not in response.headers
    assert "location" not in response.headers
    assert isinstance(response.json(), dict)


@pytest.mark.parametrize("streamed", [False, True])
def test_total_body_limit_rejects_before_writing(
    client: TestClient, streamed: bool
) -> None:
    def chunks():
        yield b"ip=10.0.0.8&padding="
        for _ in range(34):
            yield b"x" * (1024 * 1024)

    response = client.post(
        api_url("/hosts"),
        content=chunks() if streamed else b"".join(chunks()),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 413
    assert isinstance(response.json()["detail"], str)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert client.get(api_url("/hosts")).json()["rows"] == []


@pytest.mark.parametrize(
    "resource,field,fields",
    [
        ("scans", "file", {"tool": "nmap"}),
        ("operations", "attachment", {"command": "inspect"}),
    ],
)
def test_upload_limit_rejects_before_domain_writes(
    client: TestClient,
    resource: str,
    field: str,
    fields: dict[str, str],
) -> None:
    payload = SCAN_A.encode() + b" " * (32 * 1024 * 1024)
    response = client.post(
        api_url("/" + resource),
        data=fields,
        files={field: ("oversized.xml", payload, "text/xml")},
    )
    assert response.status_code == 413
    assert isinstance(response.json()["detail"], str)
    assert client.get(api_url("/scans")).json()["scans"] == []
    assert client.get(api_url("/operations")).json()["operations"] == []
    assert client.get(api_url("/hosts")).json()["rows"] == []


def test_validation_errors_are_field_addressable_without_echoing_secrets(
    client: TestClient,
) -> None:
    response = client.post(
        api_url("/credentials"),
        data={
            "username": "operator",
            "secret": "private-secret-must-not-echo",
            "host_ids": ["private-invalid-input-must-not-echo"],
        },
    )
    assert response.status_code == 422
    data = response.json()
    assert isinstance(data["detail"], str)
    assert "host_ids" in data["field_errors"]
    assert "private-secret-must-not-echo" not in response.text
    assert "private-invalid-input-must-not-echo" not in response.text
    assert "input" not in data
    assert client.get(api_url("/credentials")).json()["credentials"] == []


def test_foreign_host_mutation_returns_404_without_changing_owner(
    client: TestClient,
) -> None:
    engagement = client.post("/api/engagements", data={"name": "Other"})
    assert engagement.status_code == 200
    other_id = urlsplit(engagement.json()["redirect_to"]).path.strip("/")
    created = client.post(api_url("/hosts", other_id), data={"ip": "10.0.0.8"})
    assert created.status_code == 200
    document_path = urlsplit(created.json()["redirect_to"]).path
    host_id = document_path.rsplit("/", 1)[1]
    path = api_url(f"/hosts/{host_id}", other_id)
    response = client.patch(api_url(f"/hosts/{host_id}"), data={"ip": "10.0.0.9"})
    assert response.status_code == 404
    assert client.get(path).json()["host"]["ip"] == "10.0.0.8"
    assert client.get(api_url("/hosts")).json()["rows"] == []


def test_representative_json_responses_validate_against_openapi(
    client: TestClient,
) -> None:
    document = client.get("/openapi.json").json()
    created = client.post(api_url("/hosts"), data={"ip": "10.0.0.8"})
    assert created.status_code == 200
    host_id = urlsplit(created.json()["redirect_to"]).path.rsplit("/", 1)[1]
    detail_path = api_url(f"/hosts/{host_id}")
    responses = [
        ("/api/hosts", "post", created),
        ("/api/hosts/{host_id}", "get", client.get(detail_path)),
        ("/api/hosts", "get", client.get(api_url("/hosts"))),
        ("/api/hosts", "post", client.post(api_url("/hosts"), data={})),
        ("/api/hosts/{host_id}", "get", client.get(api_url("/hosts/999999"))),
    ]
    responses.extend(
        [
            (
                "/api/hosts/{host_id}",
                "patch",
                client.patch(detail_path, data={"ip": "10.0.0.9"}),
            ),
            (
                "/api/annotation",
                "put",
                client.put(api_url("/annotation"), data={"host_id": host_id}),
            ),
            ("/api/hosts/{host_id}", "delete", client.delete(detail_path)),
        ]
    )
    for path, method, response in responses:
        schema = document["paths"][path][method]["responses"][
            str(response.status_code)
        ]["content"]["application/json"]["schema"]
        Draft202012Validator({**schema, "components": document["components"]}).validate(
            response.json()
        )


@pytest.mark.parametrize("marker", ["", "0", "true", "2"])
def test_mutation_rejects_incorrect_request_marker_without_writing(
    client: TestClient, marker: str
) -> None:
    response = client.post(
        api_url("/hosts"),
        data={"ip": "10.0.0.8"},
        headers={"X-Penrecon-Request": marker},
    )
    assert response.status_code == 403
    assert client.get(api_url("/hosts")).json()["rows"] == []


@pytest.mark.parametrize(
    "path,fields",
    [
        ("/engagements", {"name": "Must not exist"}),
        (f"/{TEST_ENGAGEMENT_ID}/hosts", {"ip": "10.0.0.8"}),
    ],
)
def test_document_urls_do_not_accept_api_mutations(
    client: TestClient,
    path: str,
    fields: dict[str, str],
) -> None:
    response = client.post(path, data=fields)
    assert response.status_code in (404, 405)
    assert "location" not in response.headers
    assert client.get(api_url("/hosts")).json()["rows"] == []
    assert [
        entry["name"] for entry in client.get("/api/engagements").json()["catalog"]
    ] == ["Test engagement"]


def test_download_responses_are_uncacheable_and_nosniff(client: TestClient) -> None:
    created = client.post(
        api_url("/operations"),
        data={"command": "inspect"},
        files={"attachment": ("evidence.txt", b"private evidence", "text/plain")},
    )
    assert created.status_code == 200
    operation_id = client.get(api_url("/operations")).json()["operations"][0]["id"]
    attachment = client.get(
        api_url(f"/operations/{operation_id}/attachment"),
        headers={"Accept": "text/html"},
    )
    assert attachment.content == b"private evidence"
    for response in (attachment, client.get(api_url("/export/hosts.csv"))):
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "vary" not in response.headers
        assert "attachment" in response.headers["content-disposition"]


@pytest.mark.parametrize(
    "method,suffix",
    [
        ("get", "/hosts"),
        ("post", "/hosts"),
    ],
)
def test_legacy_engagement_api_prefix_is_not_an_alias(
    client: TestClient,
    method: str,
    suffix: str,
) -> None:
    response = getattr(client, method)(
        f"/api/e/{TEST_ENGAGEMENT_ID}{suffix}",
        params={"engagement_id": TEST_ENGAGEMENT_ID},
    )
    assert response.status_code == 404
    assert client.get(api_url("/hosts")).json()["rows"] == []


@pytest.mark.parametrize("method", ["PATCH", "PUT", "DELETE"])
@pytest.mark.parametrize("blocked_by", ["missing_header", "foreign_origin"])
def test_resource_mutations_require_same_origin_request_marker_without_writes(
    client: TestClient,
    method: str,
    blocked_by: str,
) -> None:
    created = client.post(api_url("/hosts"), data={"ip": "10.0.0.8"})
    assert created.status_code == 200
    host_id = urlsplit(created.json()["redirect_to"]).path.rsplit("/", 1)[1]
    host_path = api_url(f"/hosts/{host_id}")
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/services"), data={"port": "22"}
        ).status_code
        == 200
    )
    before = client.get(host_path).json()
    if method == "PUT":
        endpoint = api_url(f"/services/{before['services'][0]['service_id']}")
        fields = {"version": "must-not-write", "status": "exploited"}
    else:
        endpoint = host_path
        fields = {"ip": "10.0.0.99"}
    headers = {}
    if blocked_by == "missing_header":
        client.headers.pop("X-Penrecon-Request")
    else:
        headers["Origin"] = "http://attacker.example"
    response = client.request(method, endpoint, data=fields, headers=headers)
    assert response.status_code == 403
    assert isinstance(response.json()["detail"], str)
    assert client.get(host_path).json() == before


@pytest.mark.parametrize(
    "action_path",
    [
        "/hosts/{host_id}/edit",
        "/hosts/{host_id}/delete",
        "/credentials/{cred_id}/link/service",
    ],
)
def test_action_style_mutation_paths_are_removed_without_writes(
    client: TestClient,
    action_path: str,
) -> None:
    created = client.post(api_url("/hosts"), data={"ip": "10.0.0.8"})
    assert created.status_code == 200
    host_id = urlsplit(created.json()["redirect_to"]).path.rsplit("/", 1)[1]
    host_path = api_url(f"/hosts/{host_id}")
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/hostnames"), data={"name": "keep.example"}
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
            api_url("/notes"), data={"host_id": host_id, "title": "Keep"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            api_url("/credentials"), data={"username": "keep", "host_ids": [host_id]}
        ).status_code
        == 200
    )
    assert (
        client.post(api_url("/operations"), data={"command": "keep"}).status_code == 200
    )
    before = client.get(host_path).json()
    credentials = client.get(api_url("/credentials")).json()
    operations = client.get(api_url("/operations")).json()
    cred_id = credentials["credentials"][0]["id"]
    operation_id = operations["operations"][0]["id"]
    credential = client.get(api_url(f"/credentials/{cred_id}")).json()
    operation = client.get(api_url(f"/operations/{operation_id}")).json()
    endpoint = action_path.format(
        host_id=host_id,
        hostname_id=before["hostnames"][0][0],
        service_id=before["services"][0]["service_id"],
        cred_id=cred_id,
        note_id=before["host_notes"][0]["id"],
        operation_id=operation_id,
    )
    response = client.post(
        api_url(endpoint),
        data={
            "ip": "10.0.0.99",
            "host_id": host_id,
            "service_id": before["services"][0]["service_id"],
            "name": "Must not change",
            "username": "must-not-change",
            "command": "must-not-change",
            "title": "Must not change",
        },
    )
    assert response.status_code == 404
    assert client.get(host_path).json() == before
    assert client.get(api_url("/credentials")).json() == credentials
    assert client.get(api_url("/operations")).json() == operations
    assert client.get(api_url(f"/credentials/{cred_id}")).json() == credential
    assert client.get(api_url(f"/operations/{operation_id}")).json() == operation
    names = {
        entry["id"]: entry["name"]
        for entry in client.get("/api/engagements").json()["catalog"]
    }
    assert names[TEST_ENGAGEMENT_ID] == "Test engagement"


def test_post_resource_paths_cannot_update_or_delete_records(
    client: TestClient,
) -> None:
    created = client.post(api_url("/hosts"), data={"ip": "10.0.0.8"})
    assert created.status_code == 200
    host_id = urlsplit(created.json()["redirect_to"]).path.rsplit("/", 1)[1]
    host_path = api_url(f"/hosts/{host_id}")
    assert (
        client.post(
            api_url(f"/hosts/{host_id}/hostnames"), data={"name": "keep.example"}
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
            api_url("/notes"), data={"host_id": host_id, "title": "Keep"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            api_url("/credentials"), data={"username": "keep", "host_ids": [host_id]}
        ).status_code
        == 200
    )
    assert (
        client.post(api_url("/operations"), data={"command": "keep"}).status_code == 200
    )
    before = client.get(host_path).json()
    service_id = before["services"][0]["service_id"]
    hostname_id = before["hostnames"][0][0]
    note_id = before["host_notes"][0]["id"]
    cred_id = client.get(api_url("/credentials")).json()["credentials"][0]["id"]
    operation_id = client.get(api_url("/operations")).json()["operations"][0]["id"]
    credential = client.get(api_url(f"/credentials/{cred_id}")).json()
    operation = client.get(api_url(f"/operations/{operation_id}")).json()
    for endpoint in (
        f"/hosts/{host_id}",
        f"/hosts/{host_id}/hostnames/{hostname_id}",
        f"/services/{service_id}",
        f"/credentials/{cred_id}",
        f"/credentials/{cred_id}/hosts",
        f"/credentials/{cred_id}/services",
        f"/credentials/{cred_id}/hosts/{host_id}",
        f"/credentials/{cred_id}/services/{service_id}",
        f"/notes/{note_id}",
        f"/operations/{operation_id}",
        "/annotation",
    ):
        response = client.post(
            api_url(endpoint),
            data={
                "ip": "10.0.0.99",
                "host_id": host_id,
                "service_id": service_id,
                "username": "must-not-change",
                "command": "must-not-change",
                "title": "Must not change",
                "status": "exploited",
            },
        )
        assert response.status_code == 405, endpoint
    assert client.get(host_path).json() == before
    assert client.get(api_url(f"/credentials/{cred_id}")).json() == credential
    assert client.get(api_url(f"/operations/{operation_id}")).json() == operation
