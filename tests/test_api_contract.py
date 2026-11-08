from __future__ import annotations

from typing import Any
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


def _resolve(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema:
        assert schema["$ref"].startswith("#/")
        value = document
        for part in schema["$ref"][2:].split("/"):
            value = value[part.replace("~1", "/").replace("~0", "~")]
        schema = value
    return schema


def _assert_concrete_schema(
    document: dict[str, Any], schema: dict[str, Any], seen: frozenset[str] = frozenset()
) -> None:
    reference = schema.get("$ref")
    if reference in seen:
        return
    if reference:
        seen = seen | {reference}
    schema = _resolve(document, schema)
    variants = schema.get("anyOf") or schema.get("oneOf") or schema.get("allOf")
    if variants:
        for variant in variants:
            _assert_concrete_schema(document, variant, seen)
    elif schema.get("type") == "object":
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties")
        assert properties or isinstance(additional, dict), schema
        for child in properties.values():
            _assert_concrete_schema(document, child, seen)
        if isinstance(additional, dict):
            _assert_concrete_schema(document, additional, seen)
    elif schema.get("type") == "array":
        items = schema.get("prefixItems", []) + (
            [schema["items"]] if "items" in schema else []
        )
        assert items, schema
        for child in items:
            _assert_concrete_schema(document, child, seen)
    else:
        assert schema.get("type") in {
            "string",
            "integer",
            "number",
            "boolean",
            "null",
        }, schema


def test_openapi_documents_concrete_api_responses_and_errors(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    document = response.json()
    api_paths = {
        path: item
        for path, item in document["paths"].items()
        if path.startswith("/api/")
    }
    assert "/api/engagements" in api_paths
    assert "/api/hosts/{host_id}" in api_paths
    for path, item in api_paths.items():
        for method, operation in item.items():
            if method not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
            }:
                continue
            responses = operation["responses"]
            successes = [
                response
                for status, response in responses.items()
                if status.startswith("2")
            ]
            assert successes, (method, path)
            for success in successes:
                content = success["content"]
                assert "text/html" not in content, (method, path)
                for media in content.values():
                    _assert_concrete_schema(document, media["schema"])
            errors = {"403", "413", "422"}
            if path != "/api/engagements" or method == "put":
                errors.add("404")
            for status in errors:
                schema = responses[status]["content"]["application/json"]["schema"]
                error = _resolve(document, schema)
                assert "detail" in error["required"], (method, path, status)
                assert (
                    _resolve(document, error["properties"]["detail"])["type"]
                    == "string"
                )


@pytest.mark.parametrize(
    "path,media",
    [
        ("/api/export/hosts.csv", "text/csv"),
        ("/api/operations/{operation_id}/attachment", "application/octet-stream"),
    ],
)
def test_openapi_documents_download_media(
    client: TestClient, path: str, media: str
) -> None:
    document = client.get("/openapi.json").json()
    content = document["paths"][path]["get"]["responses"]["200"]["content"]
    assert "text/html" not in content
    assert content[media]["schema"] == {"type": "string", "format": "binary"}


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
    "method,path,statuses",
    [
        ("post", "/api/hosts", {"400"}),
        ("patch", "/api/hosts/{host_id}", {"400", "409"}),
        ("post", "/api/hosts/{host_id}/services", {"400"}),
        ("post", "/api/operations", {"400"}),
    ],
)
def test_openapi_documents_domain_errors(
    client: TestClient,
    method: str,
    path: str,
    statuses: set[str],
) -> None:
    document = client.get("/openapi.json").json()
    responses = document["paths"][path][method]["responses"]
    for status in statuses:
        schema = _resolve(
            document, responses[status]["content"]["application/json"]["schema"]
        )
        assert "detail" in schema["required"]
        assert _resolve(document, schema["properties"]["detail"])["type"] == "string"


def test_openapi_requires_query_scope_for_every_scoped_api_operation(
    client: TestClient,
) -> None:
    document = client.get("/openapi.json").json()
    scoped_operations = set()
    for path, item in document["paths"].items():
        if not path.startswith("/api/"):
            continue
        assert not path.startswith("/api/e/")
        assert "{engagement_id}" not in path
        for method, operation in item.items():
            if method not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
            }:
                continue
            parameters = [
                _resolve(document, parameter)
                for parameter in item.get("parameters", [])
                + operation.get("parameters", [])
            ]
            scope = [
                parameter
                for parameter in parameters
                if parameter["name"] == "engagement_id"
            ]
            if path == "/api/engagements" and method in {"get", "post"}:
                assert scope == []
                continue
            scoped_operations.add((method, path))
            assert len(scope) == 1, (method, path, scope)
            assert scope[0]["in"] == "query", (method, path)
            assert scope[0]["required"] is True, (method, path)
            assert _resolve(document, scope[0]["schema"])["type"] == "string", (
                method,
                path,
            )
    assert {
        ("get", "/api/hosts"),
        ("post", "/api/hosts"),
        ("get", "/api/hosts/{host_id}/services"),
        ("get", "/api/hosts/{host_id}/timeline"),
        ("get", "/api/operations"),
        ("put", "/api/engagements"),
    } <= scoped_operations


@pytest.mark.parametrize(
    "method,suffix",
    [
        ("get", "/"),
        ("get", "/bootstrap"),
        ("get", "/hosts"),
        ("post", "/hosts"),
        ("get", "/hosts/1"),
        ("get", "/hosts/1/services"),
        ("get", "/hosts/1/timeline"),
        ("get", "/data/hosts"),
        ("get", "/data/hosts/1/services"),
        ("get", "/data/hosts/1/timeline"),
        ("get", "/data/operations"),
        ("get", "/credentials"),
        ("get", "/operations"),
        ("get", "/options/hosts"),
        ("get", "/search"),
        ("get", "/scans"),
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


@pytest.mark.parametrize(
    "path",
    [
        "/api/data/hosts",
        "/api/data/hosts/1/services",
        "/api/data/hosts/1/timeline",
        "/api/data/operations",
    ],
)
def test_replaced_data_api_routes_are_removed(client: TestClient, path: str) -> None:
    assert (
        client.get(path, params={"engagement_id": TEST_ENGAGEMENT_ID}).status_code
        == 404
    )


@pytest.mark.parametrize(
    "query", ["", f"?engagement_id={TEST_ENGAGEMENT_ID}", "?engagement_id=missing"]
)
def test_bootstrap_api_is_removed(client: TestClient, query: str) -> None:
    response = client.get("/api/bootstrap" + query)
    assert response.status_code == 404
    assert "location" not in response.headers
    assert "/api/bootstrap" not in client.get("/openapi.json").json()["paths"]


def test_engagement_edit_id_path_is_removed(client: TestClient) -> None:
    response = client.post(
        f"/api/engagements/{TEST_ENGAGEMENT_ID}/edit",
        params={"engagement_id": TEST_ENGAGEMENT_ID},
        data={"name": "Must not change"},
    )
    assert response.status_code == 404
    names = {
        entry["id"]: entry["name"]
        for entry in client.get("/api/engagements").json()["catalog"]
    }
    assert names[TEST_ENGAGEMENT_ID] == "Test engagement"


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
        "/engagements/edit",
        "/hosts/{host_id}/edit",
        "/hosts/{host_id}/delete",
        "/hosts/{host_id}/hostnames/{hostname_id}/delete",
        "/services/{service_id}/edit",
        "/services/{service_id}/delete",
        "/credentials/{cred_id}/edit",
        "/credentials/{cred_id}/delete",
        "/credentials/{cred_id}/link/host",
        "/credentials/{cred_id}/link/service",
        "/credentials/{cred_id}/unlink/host/{host_id}",
        "/credentials/{cred_id}/unlink/service/{service_id}",
        "/notes/{note_id}/edit",
        "/notes/{note_id}/delete",
        "/operations/{operation_id}/edit",
        "/operations/{operation_id}/delete",
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


def test_openapi_documents_only_resource_based_mutation_methods(
    client: TestClient,
) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    mutations = {
        (method, path)
        for path, operations in paths.items()
        if path.startswith("/api/")
        for method in operations
        if method in {"post", "put", "patch", "delete"}
    }
    assert mutations == {
        ("post", "/api/engagements"),
        ("put", "/api/engagements"),
        ("post", "/api/hosts"),
        ("patch", "/api/hosts/{host_id}"),
        ("delete", "/api/hosts/{host_id}"),
        ("post", "/api/hosts/{host_id}/hostnames"),
        ("delete", "/api/hosts/{host_id}/hostnames/{hostname_id}"),
        ("post", "/api/hosts/{host_id}/services"),
        ("put", "/api/services/{service_id}"),
        ("delete", "/api/services/{service_id}"),
        ("post", "/api/credentials"),
        ("put", "/api/credentials/{cred_id}"),
        ("delete", "/api/credentials/{cred_id}"),
        ("patch", "/api/credentials/{cred_id}/hosts"),
        ("patch", "/api/credentials/{cred_id}/services"),
        ("delete", "/api/credentials/{cred_id}/hosts/{host_id}"),
        ("delete", "/api/credentials/{cred_id}/services/{service_id}"),
        ("post", "/api/notes"),
        ("put", "/api/notes/{note_id}"),
        ("delete", "/api/notes/{note_id}"),
        ("put", "/api/annotation"),
        ("post", "/api/operations"),
        ("put", "/api/operations/{operation_id}"),
        ("delete", "/api/operations/{operation_id}"),
        ("post", "/api/scans"),
    }
    for path in paths:
        assert not {"edit", "delete", "link", "unlink"} & set(path.split("/")), path
    for path in (
        "/api/services/{service_id}",
        "/api/credentials/{cred_id}",
        "/api/notes/{note_id}",
        "/api/annotation",
    ):
        content = paths[path]["put"]["requestBody"]["content"]
        assert "application/x-www-form-urlencoded" in content
    assert (
        "multipart/form-data"
        in paths["/api/operations/{operation_id}"]["put"]["requestBody"]["content"]
    )
