from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import delete
from sqlmodel import Session, select

from penrecon import projections
from penrecon.ingest import ingest_scan
from penrecon.models import (
    Annotation,
    CurrentService,
    Engagement,
    Host,
    HostHostname,
    Hostname,
    HostScanDelta,
    HostScanEvidence,
    HostScanState,
    HostSummary,
    HostSummaryTag,
    HostTimelineEntry,
    ManualServiceEvent,
    Note,
    Observation,
    ObsState,
    Scan,
    Service,
    Status,
)
from penrecon.queries.inventory import (
    host_page,
    host_rows,
    host_timeline,
    latest_observations,
    resolved_services,
    service_page,
)
from tests.fixtures import SCAN_A, SCAN_B, TEST_ENGAGEMENT_ID


def _scan_host(session: Session, engagement_id: str = TEST_ENGAGEMENT_ID) -> Host:
    ingest_scan(
        session, SCAN_A.encode(), "baseline.xml", "nmap", engagement_id=engagement_id
    )
    return session.exec(
        select(Host).where(
            Host.engagement_id == engagement_id,
            Host.ip == "10.0.0.1",
        )
    ).one()


def _service(session: Session, host: Host, port: int = 22) -> Service:
    return session.exec(
        select(Service).where(
            Service.engagement_id == host.engagement_id,
            Service.host_id == host.id,
            Service.port == port,
        )
    ).one()


def _manual_host(
    session: Session, ip: str, engagement_id: str = TEST_ENGAGEMENT_ID
) -> Host:
    host = Host(ip=ip, engagement_id=engagement_id)
    session.add(host)
    session.flush()
    assert host.id is not None
    return host


@pytest.mark.parametrize("flushed", [False, True], ids=["pending", "flushed"])
def test_manual_override_reads_refresh_services_and_open_host_filters(
    session: Session,
    flushed: bool,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host)
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 1
    assert (
        resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[0].version
        == "8.9"
    )

    service.m_state = ObsState.filtered
    service.m_service_name = "SÉCURE-shell"
    service.m_product = "Manual Product"
    service.m_version = "manual-version"
    if flushed:
        session.flush()

    services = service_page(
        session,
        host.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        state="filtered",
        service="sécure-shell manual product manual-version",
    )
    assert services.total == 1
    view = services.services[0]
    assert (view.state, view.service_name, view.product, view.version, view.manual) == (
        "filtered",
        "SÉCURE-shell",
        "Manual Product",
        "manual-version",
        True,
    )
    assert view.overrides.version == "manual-version"
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 0
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="sécure").matched == 0
    row = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    assert (row.open_count, row.open_services) == (1, [(80, "http")])

    service.m_state = ObsState.open
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, q="sécure", port=22
        ).matched
        == 1
    )
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0].open_count == 2


def test_rollback_restores_projected_manual_values_and_host_filters(
    session: Session,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host)
    host_id = host.id
    service.m_state = ObsState.closed
    session.add(
        Annotation(
            engagement_id=TEST_ENGAGEMENT_ID,
            host_id=host_id,
            status=Status.interesting,
            tags=["temporary"],
        )
    )
    assert (
        host_page(
            session,
            engagement_id=TEST_ENGAGEMENT_ID,
            tag="temporary",
            status="interesting",
        ).matched
        == 1
    )
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 0
    session.rollback()

    row = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    assert (row.open_count, row.status, row.tags, row.triaged) == (2, "new", [], False)
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="temporary").matched
        == 0
    )
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 1
    view = resolved_services(session, host_id, engagement_id=TEST_ENGAGEMENT_ID)[0]
    assert (view.state, view.version, view.manual) == ("open", "8.9", False)


@pytest.mark.parametrize(
    "inner_write", [False, True], ids=["read-only-savepoint", "changed-savepoint"]
)
def test_savepoint_rollback_retains_outer_write_invalidation(
    session: Session,
    inner_write: bool,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host)
    # begin_nested flushes these outer writes; the first projection read occurs
    # inside the savepoint, so rolling it back must not lose their invalidation.
    service.m_state = ObsState.closed
    annotation = Annotation(
        engagement_id=TEST_ENGAGEMENT_ID,
        host_id=host.id,
        status=Status.reviewed,
        tags=["outer"],
    )
    session.add(annotation)
    with session.begin_nested() as savepoint:
        assert (
            host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 0
        )
        assert (
            host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="outer").matched
            == 1
        )
        if inner_write:
            service.m_state = ObsState.open
            annotation.tags = ["inner"]
            session.flush()
            assert (
                host_page(
                    session, engagement_id=TEST_ENGAGEMENT_ID, port=22, tag="inner"
                ).matched
                == 1
            )
        savepoint.rollback()

    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 0
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, tag="outer", status="reviewed"
        ).matched
        == 1
    )
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="inner").matched == 0
    )
    assert (
        resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[0].state
        == "closed"
    )
    session.commit()
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0].open_count == 1


@pytest.mark.parametrize("target", ["host", "service"])
def test_delete_then_reimport_does_not_resurrect_stale_inventory_metadata(
    session: Session,
    target: str,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host)
    assert service.id is not None
    service.m_service_name = "deleted-override"
    service.m_version = "deleted-version"
    session.add_all(
        [
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID, host_id=host.id, tags=["host-tag"]
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID,
                service_id=service.id,
                status=Status.exploited,
                tags=["service-tag"],
            ),
        ]
    )
    session.commit()
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, port=22, q="deleted-override"
        ).matched
        == 1
    )

    session.delete(host if target == "host" else service)
    session.flush()
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=22).matched == 0
    remaining_services = resolved_services(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID
    )
    assert [view.port for view in remaining_services] == (
        [] if target == "host" else [80]
    )
    remaining = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
    if target == "host":
        assert remaining == []
    else:
        assert remaining[0].open_services == [(80, "http")]
    session.commit()

    ingest_scan(
        session,
        SCAN_B.encode(),
        "reimport.xml",
        "nmap",
        engagement_id=TEST_ENGAGEMENT_ID,
    )
    row = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    assert (row.open_count, row.open_services) == (2, [(22, "ssh"), (443, "https")])
    assert row.tags == ([] if target == "host" else ["host-tag"])
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, q="deleted-override"
        ).matched
        == 0
    )
    views = resolved_services(session, row.id, engagement_id=TEST_ENGAGEMENT_ID)
    ssh = next(view for view in views if view.port == 22)
    assert (ssh.version, ssh.manual, ssh.annotation) == ("9.0", False, None)
    assert (
        service_page(
            session, row.id, engagement_id=TEST_ENGAGEMENT_ID, status="exploited"
        ).total
        == 0
    )


def test_clearing_overrides_reveals_latest_scan_and_updates_open_filters(
    session: Session,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host, 80)
    service.m_state = ObsState.open
    service.m_service_name = "manual-web"
    service.m_version = "manual-version"
    session.commit()
    ingest_scan(
        session, SCAN_B.encode(), "newer.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, port=80, q="manual-web"
        ).matched
        == 1
    )
    before = next(
        view
        for view in resolved_services(
            session, host.id, engagement_id=TEST_ENGAGEMENT_ID
        )
        if view.port == 80
    )
    assert (before.state, before.version, before.manual) == (
        "open",
        "manual-version",
        True,
    )

    service.m_state = None
    service.m_service_name = None
    service.m_version = None
    inherited = service_page(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID, state="closed"
    )
    assert inherited.total == 1
    assert (
        inherited.services[0].port,
        inherited.services[0].service_name,
        inherited.services[0].version,
    ) == (
        80,
        "http",
        "2.4.1",
    )
    assert inherited.services[0].manual is False
    assert inherited.services[0].overrides.version is None
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=80).matched == 0
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="manual-web").matched
        == 0
    )
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0].open_services == [
        (22, "ssh"),
        (443, "https"),
    ]
    evidence = latest_observations(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[
        (80, "tcp")
    ]
    assert (evidence.state, evidence.service_name, evidence.version) == (
        "closed",
        "http",
        "2.4.1",
    )


def test_annotation_changes_and_deletion_refresh_host_and_service_filters(
    session: Session,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host)
    assert service.id is not None
    host_annotation = Annotation(
        engagement_id=TEST_ENGAGEMENT_ID,
        host_id=host.id,
        status=Status.reviewed,
        tags=["old-tag"],
    )
    service_annotation = Annotation(
        engagement_id=TEST_ENGAGEMENT_ID,
        service_id=service.id,
        status=Status.interesting,
        tags=["service-only"],
    )
    session.add_all([host_annotation, service_annotation])
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, tag="old-tag", status="reviewed"
        ).matched
        == 1
    )
    assert (
        service_page(
            session, host.id, engagement_id=TEST_ENGAGEMENT_ID, status="interesting"
        ).total
        == 1
    )
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="service-only").matched
        == 0
    )

    host_annotation.tags = ["new-tag", "new-tag"]
    host_annotation.status = Status.new
    service_annotation.status = Status.exploited
    session.flush()
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="old-tag").matched == 0
    )
    row = host_page(
        session, engagement_id=TEST_ENGAGEMENT_ID, tag="new-tag", status="new"
    ).rows[0]
    assert row.triaged is True
    assert row.tags == ["new-tag", "new-tag"]
    page = service_page(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID, status="exploited"
    )
    assert page.total == 1
    assert page.services[0].annotation is not None
    assert page.services[0].annotation.tags == ["service-only"]

    session.delete(host_annotation)
    session.delete(service_annotation)
    session.flush()
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="new-tag").matched == 0
    )
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0].triaged is False
    assert (
        service_page(
            session, host.id, engagement_id=TEST_ENGAGEMENT_ID, status="exploited"
        ).total
        == 0
    )
    assert (
        resolved_services(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)[
            0
        ].annotation
        is None
    )


def test_hostname_rename_visibility_and_cascade_refresh_substring_filters(
    session: Session,
) -> None:
    host = _manual_host(session, "10.0.0.30")
    assert host.id is not None
    hostname = Hostname(engagement_id=TEST_ENGAGEMENT_ID, name="Before.Example")
    session.add(hostname)
    session.flush()
    assert hostname.id is not None
    link = HostHostname(
        engagement_id=TEST_ENGAGEMENT_ID,
        host_id=host.id,
        hostname_id=hostname.id,
    )
    session.add(link)
    session.commit()
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="before").matched == 1

    hostname.name = "Äfter.Example"
    session.flush()
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="before").matched == 0
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="ÄFTER").rows[
        0
    ].hostnames == ["Äfter.Example"]
    link.hidden = True
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="äfter").matched == 0
    link.hidden = False
    session.flush()
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="äfter").matched == 1

    session.delete(hostname)
    session.flush()
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="äfter").matched == 0
    assert host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0].hostnames == []


def test_host_ip_edit_refreshes_search_and_numeric_sort_key(session: Session) -> None:
    edited = _manual_host(session, "10.0.0.3")
    _manual_host(session, "10.0.0.10")
    session.commit()
    assert [
        row.ip
        for row in host_page(session, engagement_id=TEST_ENGAGEMENT_ID, sort="ip").rows
    ] == [
        "10.0.0.3",
        "10.0.0.10",
    ]

    edited.ip = "10.0.0.20"
    assert [
        row.ip
        for row in host_page(session, engagement_id=TEST_ENGAGEMENT_ID, sort="ip").rows
    ] == [
        "10.0.0.10",
        "10.0.0.20",
    ]
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="10.0.0.3").matched == 0
    )
    assert (
        host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q="10.0.0.20").rows[0].id
        == edited.id
    )


def test_tag_filters_are_exact_and_ports_match_only_explicitly_open_services(
    session: Session,
) -> None:
    both = _manual_host(session, "10.0.0.40")
    closed = _manual_host(session, "10.0.0.41")
    prefix = _manual_host(session, "10.0.0.42")
    ambiguous = _manual_host(session, "10.0.0.43")
    session.add_all(
        [
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=both.id,
                port=80,
                proto="tcp",
                m_state=ObsState.open,
            ),
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=both.id,
                port=80,
                proto="udp",
                m_state=ObsState.open,
                m_service_name="udp-web",
            ),
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=closed.id,
                port=80,
                proto="tcp",
                m_state=ObsState.closed,
            ),
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=prefix.id,
                port=8080,
                proto="tcp",
                m_state=ObsState.open,
            ),
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=ambiguous.id,
                port=80,
                proto="tcp",
                m_state=ObsState.open_filtered,
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID, host_id=both.id, tags=["prod"]
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID, host_id=closed.id, tags=["production"]
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID, host_id=prefix.id, tags=["Prod"]
            ),
        ]
    )
    session.commit()
    matches = host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=80, tag="prod")
    assert (matches.total, matches.matched) == (4, 1)
    assert [row.id for row in matches.rows] == [both.id]
    assert matches.rows[0].open_count == 2
    assert matches.rows[0].open_ports == [80, 80]
    assert set(matches.rows[0].open_services) == {(80, None), (80, "udp-web")}
    assert [
        row.id
        for row in host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=80).rows
    ] == [both.id]
    assert [
        row.id
        for row in host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="Prod").rows
    ] == [prefix.id]
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, tag="pro").matched == 0
    assert host_page(session, engagement_id=TEST_ENGAGEMENT_ID, port=8).matched == 0


def test_unicode_substrings_are_literal_and_do_not_span_host_search_fields(
    session: Session,
) -> None:
    host = _manual_host(session, "10.0.0.50")
    assert host.id is not None
    hostname = Hostname(engagement_id=TEST_ENGAGEMENT_ID, name="Äpfel.Example")
    session.add(hostname)
    session.flush()
    assert hostname.id is not None
    session.add_all(
        [
            HostHostname(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=host.id,
                hostname_id=hostname.id,
            ),
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=host.id,
                port=443,
                proto="tcp",
                m_state=ObsState.open,
                m_service_name="MÜNCHEN_100%",
                m_product="OnlyProduct",
                m_version="vX",
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=host.id,
                tags=["ÖPS", "alpha", "beta"],
            ),
        ]
    )
    session.commit()
    for needle in ("äPFEL", "münCHEN_100%", "öps", "%", "_"):
        assert (
            host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q=needle).matched == 1
        )
    for needle in (
        "example münchen",
        "alpha beta",
        "10.0.0.50 äpfel",
        "OnlyProduct",
        "vX",
        '","',
    ):
        assert (
            host_page(session, engagement_id=TEST_ENGAGEMENT_ID, q=needle).matched == 0
        )
    assert (
        service_page(
            session, host.id, engagement_id=TEST_ENGAGEMENT_ID, service="münchen_100%"
        ).total
        == 1
    )
    assert (
        service_page(
            session, host.id, engagement_id=TEST_ENGAGEMENT_ID, service="onlyproduct vx"
        ).total
        == 1
    )


def test_inventory_invalidation_and_filters_remain_engagement_scoped(
    session: Session,
) -> None:
    own = _scan_host(session)
    other = Engagement(name="Other inventory")
    session.add(other)
    session.commit()
    foreign = _scan_host(session, other.id)
    assert own.id is not None and foreign.id is not None
    own_service = _service(session, own)
    foreign_service = _service(session, foreign)
    own_service.m_service_name = "own-only"
    foreign_service.m_service_name = "foreign-only"
    foreign_service.m_state = ObsState.closed
    session.add(
        Annotation(
            engagement_id=other.id,
            host_id=foreign.id,
            status=Status.exploited,
            tags=["foreign-tag"],
        )
    )
    session.flush()
    for filters in (
        {"q": "foreign-only"},
        {"tag": "foreign-tag"},
        {"status": "exploited"},
    ):
        page = host_page(session, engagement_id=TEST_ENGAGEMENT_ID, **filters)
        assert (page.total, page.matched) == (1, 0)
    own_page = host_page(
        session, engagement_id=TEST_ENGAGEMENT_ID, q="own-only", port=22
    )
    assert [row.id for row in own_page.rows] == [own.id]
    assert host_page(session, engagement_id=other.id, port=22).matched == 0
    assert (
        resolved_services(session, foreign.id, engagement_id=TEST_ENGAGEMENT_ID) == []
    )
    assert service_page(session, own.id, engagement_id=other.id).total == 0

    session.delete(foreign)
    session.commit()
    assert host_page(session, engagement_id=other.id).total == 0
    assert (
        host_page(
            session, engagement_id=TEST_ENGAGEMENT_ID, q="own-only", port=22
        ).matched
        == 1
    )


def test_additive_backfill_uses_existing_scan_state_without_changing_user_data(
    session: Session,
) -> None:
    host = _scan_host(session)
    assert host.id is not None
    service = _service(session, host)
    assert service.id is not None
    service.m_version = "preserved-manual"
    link = session.exec(
        select(HostHostname).where(HostHostname.host_id == host.id)
    ).one()
    link.hidden = True
    manual_host = _manual_host(session, "10.0.0.99")
    assert manual_host.id is not None
    session.add_all(
        [
            Service(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=manual_host.id,
                port=9000,
                proto="tcp",
                m_state=ObsState.open,
                m_service_name="manual-only",
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=host.id,
                status=Status.reviewed,
                tags=["keep-tag"],
            ),
            Annotation(
                engagement_id=TEST_ENGAGEMENT_ID,
                service_id=service.id,
                status=Status.interesting,
                tags=["keep-service-tag"],
            ),
            Note(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=host.id,
                title="Keep note",
                body_md="User content",
            ),
            ManualServiceEvent(
                engagement_id=TEST_ENGAGEMENT_ID,
                host_id=host.id,
                port=22,
                proto="tcp",
                occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
                kind="changed",
                before={
                    "state": "open",
                    "service_name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9",
                },
                after={
                    "state": "open",
                    "service_name": "ssh",
                    "product": "OpenSSH",
                    "version": "preserved-manual",
                },
            ),
        ]
    )
    session.commit()
    before_rows = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)
    before_services = resolved_services(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID
    )
    before_timeline = host_timeline(
        session, host.id, engagement_id=TEST_ENGAGEMENT_ID, show_unchanged=True
    )
    source_models = (
        Scan,
        Host,
        Service,
        Hostname,
        HostHostname,
        Annotation,
        Note,
        Observation,
        HostScanEvidence,
        HostScanState,
        HostScanDelta,
        ManualServiceEvent,
    )
    before_sources = {
        model: [row.model_dump() for row in session.exec(select(model)).all()]
        for model in source_models
    }
    engine = session.get_bind()
    session.commit()
    # Simulate the pre-additive schema's missing read-model contents, leaving
    # already-complete scan projections and all source/user rows intact.
    with engine.begin() as connection:
        for model in (HostSummaryTag, HostSummary, CurrentService, HostTimelineEntry):
            connection.execute(delete(model))

    with Session(engine) as restored:
        projections.backfill_missing(restored)
        restored.commit()
        projections.backfill_missing(restored)
        restored.commit()
        assert host_rows(restored, engagement_id=TEST_ENGAGEMENT_ID) == before_rows
        services = resolved_services(
            restored, host.id, engagement_id=TEST_ENGAGEMENT_ID
        )
        assert [
            (view.port, view.state, view.version, view.manual, view.overrides)
            for view in services
        ] == [
            (view.port, view.state, view.version, view.manual, view.overrides)
            for view in before_services
        ]
        assert services[0].annotation is not None
        assert services[0].annotation.tags == ["keep-service-tag"]
        assert (
            host_page(
                restored,
                engagement_id=TEST_ENGAGEMENT_ID,
                tag="keep-tag",
                status="reviewed",
            ).matched
            == 1
        )
        assert (
            host_page(restored, engagement_id=TEST_ENGAGEMENT_ID, q="a.example").matched
            == 0
        )
        assert (
            host_page(
                restored, engagement_id=TEST_ENGAGEMENT_ID, q="manual-only", port=9000
            ).matched
            == 1
        )
        assert (
            host_timeline(
                restored, host.id, engagement_id=TEST_ENGAGEMENT_ID, show_unchanged=True
            )
            == before_timeline
        )
        for model, expected in before_sources.items():
            assert [
                row.model_dump() for row in restored.exec(select(model)).all()
            ] == expected
