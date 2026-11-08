from __future__ import annotations

from urllib.parse import urlencode

import pytest
from starlette.testclient import TestClient

from tests.fixtures import api_url


def _upload(client: TestClient, hosts: list[tuple[str, int, str]], filename: str) -> None:
    records = []
    for ip, open_count, version in hosts:
        ports = "".join(
            f'<port protocol="tcp" portid="{port}"><state state="open"/>'
            f'<service name="http" version="{version}"/></port>'
            for port in range(8000, 8000 + open_count)
        )
        records.append(
            '<host><status state="up"/>'
            f'<address addr="{ip}" addrtype="{"ipv6" if ":" in ip else "ipv4"}"/>'
            f'<ports>{ports}</ports></host>'
        )
    response = client.post(
        api_url("/scans"),
        files={"file": (filename, "<nmaprun>" + "".join(records) + "</nmaprun>", "text/xml")},
        data={"tool": "nmap"},
    )
    assert response.status_code == 200


def _hosts(client: TestClient, **params) -> dict:
    response = client.get(api_url("/hosts?" + urlencode(params)))
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize(
    ("direction", "expected"),
    [
        ("asc", ["10.0.0.1", "10.0.0.2", "10.0.0.10", "2001:db8::1", "2001:db8::2"]),
        ("desc", ["2001:db8::1", "2001:db8::2", "10.0.0.10", "10.0.0.2", "10.0.0.1"]),
    ],
)
def test_ip_sort_respects_direction(client: TestClient, direction: str, expected: list[str]) -> None:
    _upload(client, [
        ("10.0.0.2", 0, ""), ("2001:db8::2", 0, ""), ("10.0.0.10", 0, ""),
        ("2001:db8::1", 0, ""), ("10.0.0.1", 0, ""),
    ], "ips.xml")
    data = _hosts(client, sort="ip", dir=direction)
    assert [row["ip"] for row in data["rows"]] == expected
    assert data["direction"] == direction


@pytest.mark.parametrize(("direction", "expected"), [("desc", [9, 3, 1]), ("asc", [1, 3, 9])])
def test_ports_sort_direction(client: TestClient, direction: str, expected: list[int]) -> None:
    _upload(client, [("10.0.0.1", 1, ""), ("10.0.0.2", 9, ""), ("10.0.0.3", 3, "")], "ports.xml")
    data = _hosts(client, sort="ports", dir=direction)
    assert [row["open_count"] for row in data["rows"]] == expected


def _change_inventory(client: TestClient) -> None:
    _upload(client, [
        ("10.0.0.1", 9, "1"), ("10.0.0.3", 5, "1"), ("10.0.0.5", 1, "1"),
    ], "baseline.xml")
    _upload(client, [
        ("10.0.0.1", 9, "1"), ("10.0.0.2", 2, "1"), ("10.0.0.3", 5, "2"),
        ("10.0.0.4", 7, "1"), ("10.0.0.5", 1, "1"),
    ], "latest.xml")


@pytest.mark.parametrize(
    ("direction", "expected"),
    [
        ("asc", ["10.0.0.4", "10.0.0.2", "10.0.0.3", "10.0.0.1", "10.0.0.5"]),
        ("desc", ["10.0.0.1", "10.0.0.5", "10.0.0.3", "10.0.0.4", "10.0.0.2"]),
    ],
)
def test_change_sort_keeps_ports_descending_within_groups(
    client: TestClient, direction: str, expected: list[str],
) -> None:
    _change_inventory(client)
    data = _hosts(client, sort="change", dir=direction)
    assert [row["ip"] for row in data["rows"]] == expected


def test_filter_by_change_preserves_counts_and_default_order(client: TestClient) -> None:
    _change_inventory(client)
    for change, expected in [
        ("new", ["10.0.0.4", "10.0.0.2"]),
        ("changed", ["10.0.0.3"]),
        ("unchanged", ["10.0.0.1", "10.0.0.5"]),
    ]:
        data = _hosts(client, change=change)
        assert [row["ip"] for row in data["rows"]] == expected
        assert (data["total"], data["matched"]) == (5, len(expected))
        assert (data["sort"], data["direction"]) == ("change", "asc")
    assert _hosts(client, change="")["matched"] == 5


def test_host_pagination_slices_clamps_and_handles_empty_matches(client: TestClient) -> None:
    _upload(client, [(f"10.0.0.{index}", 0, "") for index in range(1, 26)], "pages.xml")
    first = _hosts(client, sort="ip", per="10", page="1")
    assert [row["ip"] for row in first["rows"]] == [f"10.0.0.{index}" for index in range(1, 11)]
    assert (first["total"], first["matched"], first["page"], first["pages"]) == (25, 25, 1, 3)

    last = _hosts(client, sort="ip", per="10", page="99")
    assert [row["ip"] for row in last["rows"]] == [f"10.0.0.{index}" for index in range(21, 26)]
    assert (last["page"], last["pages"]) == (3, 3)
    assert _hosts(client, sort="ip", per="10", page="3")["rows"] == last["rows"]
    assert _hosts(client, sort="ip", page="0")["page"] == 1

    all_rows = _hosts(client, sort="ip", per="all", page="99")
    assert (len(all_rows["rows"]), all_rows["page"], all_rows["pages"]) == (25, 1, 1)
    empty = _hosts(client, q="not-present", page="99")
    assert empty["rows"] == []
    assert (empty["total"], empty["matched"], empty["page"], empty["pages"]) == (25, 0, 1, 1)
