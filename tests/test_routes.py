from __future__ import annotations

from starlette.testclient import TestClient

# NOTE: the `client` fixture (conftest) overrides get_session with an in-memory DB.
# To seed data into that SAME db from a test, go through the app's own routes,
# not a separate session — the override's engine is not exposed. Seed via HTTP.


def test_index_full_page(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "<html" in r.text.lower() or "<!doctype" in r.text.lower()


def test_index_htmx_returns_fragment(client: TestClient) -> None:
    r = client.get("/", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text.lower()


def test_missing_host_404(client: TestClient) -> None:
    r = client.get("/hosts/999999")
    assert r.status_code == 404
    assert "not found" in r.text.lower()


def test_create_host_redirects_to_detail(client: TestClient) -> None:
    r = client.post("/hosts", data={"ip": "10.0.0.5"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/hosts/")
    detail = client.get(r.headers["location"])
    assert detail.status_code == 200
    assert "10.0.0.5" in detail.text


def test_create_host_rejects_bad_ip(client: TestClient) -> None:
    r = client.post("/hosts", data={"ip": "not-an-ip"}, follow_redirects=False)
    assert r.status_code == 400
    assert "not a valid" in r.text.lower()


def test_delete_host_redirects_home(client: TestClient) -> None:
    created = client.post("/hosts", data={"ip": "10.0.0.6"}, follow_redirects=False)
    host_path = created.headers["location"]  # /hosts/{id}
    host_id = host_path.rsplit("/", 1)[1]
    r = client.post(f"/hosts/{host_id}/delete", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"


def test_export_csv_headers(client: TestClient) -> None:
    r = client.get("/export/hosts.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]


def test_create_credential_lists_it(client: TestClient) -> None:
    r = client.post(
        "/credentials",
        data={"kind": "password", "username": "root", "secret": "toor"},
    )
    assert r.status_code == 200
    assert "root" in r.text


def test_scans_and_diff_pages_render(client: TestClient) -> None:
    assert client.get("/scans").status_code == 200
    assert client.get("/diff").status_code == 200


def test_upload_scan_then_host_appears(client: TestClient) -> None:
    from tests.fixtures import SCAN_A

    r = client.post(
        "/scans",
        files={"file": ("a.xml", SCAN_A, "text/xml")},
        data={"tool": "nmap"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    idx = client.get("/")
    assert "10.0.0.1" in idx.text


def test_edit_host_rejects_duplicate_ip(client: TestClient) -> None:
    client.post("/hosts", data={"ip": "10.0.0.10"}, follow_redirects=False)
    b = client.post("/hosts", data={"ip": "10.0.0.11"}, follow_redirects=False)
    b_id = b.headers["location"].rsplit("/", 1)[1]
    # try to rename host B onto host A's IP
    r = client.post(f"/hosts/{b_id}/edit", data={"ip": "10.0.0.10"}, follow_redirects=False)
    assert r.status_code == 409
    assert "already belongs to another host" in r.text
    # host B is unchanged
    detail = client.get(f"/hosts/{b_id}")
    assert "10.0.0.11" in detail.text


def test_edit_host_accepts_new_ip(client: TestClient) -> None:
    a = client.post("/hosts", data={"ip": "10.0.0.12"}, follow_redirects=False)
    a_id = a.headers["location"].rsplit("/", 1)[1]
    r = client.post(f"/hosts/{a_id}/edit", data={"ip": "10.0.0.99"}, follow_redirects=False)
    assert r.status_code == 303
    detail = client.get(f"/hosts/{a_id}")
    assert "10.0.0.99" in detail.text
