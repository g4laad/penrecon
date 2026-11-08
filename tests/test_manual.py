from __future__ import annotations

import pytest
from urllib.parse import urlencode, parse_qs, urlsplit

from tests.fixtures import api_url, TEST_ENGAGEMENT_ID
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from penrecon.ingest import ingest_scan
from penrecon.models import Host, HostHostname, ObsState, Service
from penrecon.queries import host_hostnames, latest_observations, resolved_services


def _scan(ip: str, port: int, version: str, hostname: str) -> bytes:
    return (
        f'<?xml version="1.0"?><nmaprun><host><status state="up"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<hostnames><hostname name="{hostname}" type="user"/></hostnames>'
        f'<ports><port protocol="tcp" portid="{port}"><state state="open"/>'
        f'<service name="http" product="nginx" version="{version}" method="probed"/>'
        f"</port></ports></host></nmaprun>"
    ).encode()


def test_manual_override_wins_over_rescan(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.1", 443, "1.25", "a.example"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    svc = session.exec(select(Service).where(Service.port == 443)).one()
    svc.m_version = "9.9-manual"
    session.commit()

    # a newer scan reports a different version
    ingest_scan(session, _scan("10.0.0.1", 443, "2.0", "a.example"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)

    host = session.exec(select(Host).where(Host.ip == "10.0.0.1")).one()
    assert host.id is not None
    view = {s.port: s for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert view[443].version == "9.9-manual"  # manual wins, not scan's 2.0


def test_deleted_service_reappears_fresh_on_rescan(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.2", 22, "1.0", "b.example"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = session.exec(select(Host).where(Host.ip == "10.0.0.2")).one()
    assert host.id is not None
    svc = session.exec(select(Service).where(Service.port == 22)).one()

    # Delete only current identity/overrides; immutable scan evidence survives.
    svc.m_version = "discard-on-delete"
    session.commit()
    session.delete(svc)
    session.commit()
    assert 22 not in {s.port for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}  # truly gone
    assert latest_observations(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[(22, "tcp")].version == "1.0"

    # a later scan re-creates it fresh (new row, new observation)
    ingest_scan(session, _scan("10.0.0.2", 22, "2.0", "b.example"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    view = {s.port: s for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert 22 in view
    assert view[22].version == "2.0"  # fresh from the new scan, nothing stale


def test_hidden_hostname_stays_hidden_across_rescan(session: Session) -> None:
    ingest_scan(session, _scan("10.0.0.3", 80, "1.0", "keep.example"), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    host = session.exec(select(Host).where(Host.ip == "10.0.0.3")).one()
    assert host.id is not None
    link = session.exec(
        select(HostHostname).where(HostHostname.host_id == host.id)
    ).one()
    link.hidden = True
    session.commit()

    ingest_scan(session, _scan("10.0.0.3", 80, "1.0", "keep.example"), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID)
    assert host_hostnames(session, host.id, engagement_id=TEST_ENGAGEMENT_ID) == []  # sticky delete, not resurrected


def test_manual_only_service_shows(session: Session) -> None:
    # a service added by hand with no scan observation still appears
    host = Host(ip="10.0.0.4", engagement_id=TEST_ENGAGEMENT_ID)
    session.add(host)
    session.commit()
    session.refresh(host)
    assert host.id is not None
    session.add(Service(host_id=host.id, port=8080, proto="tcp", m_state=ObsState.open,
                        m_service_name="http-proxy", engagement_id=TEST_ENGAGEMENT_ID))
    session.commit()

    view = {s.port: s for s in resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)}
    assert view[8080].state == "open"
    assert view[8080].service_name == "http-proxy"
    assert view[8080].manual is True


def test_missing_host_mutations_return_not_found(client: TestClient) -> None:
    for method, data in (("PATCH", {"ip": "10.0.0.99"}), ("DELETE", {})):
        response = client.request(method, api_url("/hosts/999"), data=data)
        assert response.status_code == 404
        assert response.json()["detail"] == "host not found"


def test_foreign_host_mutations_return_not_found_without_changing_inventory(client: TestClient) -> None:
    created = client.post(api_url(f"/hosts"), data={"ip": "10.0.0.99"})
    assert created.status_code == 200
    engagement_id, _, host_id = urlsplit(created.json()["redirect_to"]).path.strip("/").split("/")[1:]
    host_path = api_url(f"/hosts/{host_id}", engagement_id)
    host_id = urlsplit(host_path).path.rsplit("/", 1)[1]
    engagement = client.post("/api/engagements", data={"name": "Other inventory"})
    assert engagement.status_code == 200
    foreign_id = urlsplit(engagement.json()["redirect_to"]).path.strip("/").split("/")[1]
    for method, data in (("PATCH", {"ip": "10.0.0.100"}), ("DELETE", {})):
        response = client.request(method, api_url(f"/hosts/{host_id}", foreign_id), data=data)
        assert response.status_code == 404
        assert response.json()["detail"] == "host not found"
    assert client.get(host_path).json()["host"]["ip"] == "10.0.0.99"
    assert client.get(api_url("/hosts", foreign_id)).json()["rows"] == []


@pytest.mark.parametrize("raw", ["²", "٢", "not-a-number", "12345678901", "9" * 5000])
def test_malformed_inventory_numbers_use_safe_defaults(client: TestClient, raw: str) -> None:
    created = client.post(api_url(f"/hosts"), data={"ip": "10.0.0.99"})
    assert created.status_code == 200
    engagement_id, _, host_id = urlsplit(created.json()["redirect_to"]).path.strip("/").split("/")[1:]
    host_path = api_url(f"/hosts/{host_id}", engagement_id)
    host_id = urlsplit(host_path).path.rsplit("/", 1)[1]
    added = client.post(api_url(urlsplit(host_path).path.removeprefix("/api") + "/services", parse_qs(urlsplit(host_path).query)["engagement_id"][0]), data={"port": "443", "service_name": "https"})
    assert added.status_code == 200

    for path in (api_url("/hosts"),):
        response = client.get(api_url(urlsplit(path).path.removeprefix("/api") + "?" + urlencode({"port": raw, "page": raw, "per": raw}), parse_qs(urlsplit(path).query)["engagement_id"][0]))
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["matched"] == 1
        assert data["rows"][0]["ip"] == "10.0.0.99"

    for path in (host_path, api_url(f"/hosts/{host_id}/services")):
        response = client.get(api_url(urlsplit(path).path.removeprefix("/api") + "?" + urlencode({"page": raw, "per": raw}), parse_qs(urlsplit(path).query)["engagement_id"][0]))
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["svc_total"] == 1
        assert data["services"][0]["port"] == 443
