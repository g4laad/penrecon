from __future__ import annotations

import pytest
from sqlmodel import Session, select

from penrecon.history import host_history
from penrecon.ingest import ingest_scan
from penrecon.models import Engagement, Host, Observation, ObsState, Scan
from penrecon.queries.diff import diff_scans
from penrecon.queries.inventory import host_rows
from tests.fixtures import SCAN_A, SCAN_B, TEST_ENGAGEMENT_ID


def _scan(
    session: Session,
    filename: str,
    *,
    engagement_id: str = TEST_ENGAGEMENT_ID,
) -> Scan:
    scan = Scan(
        engagement_id=engagement_id,
        filename=filename,
        tool="nmap",
        source_format="nmap",
    )
    session.add(scan)
    session.flush()
    return scan


def _observe(
    session: Session,
    scan: Scan,
    ip: str,
    port: int,
    proto: str = "tcp",
    *,
    state: ObsState = ObsState.open,
    service_name: str | None = None,
    product: str | None = None,
    version: str | None = None,
) -> None:
    host = session.exec(
        select(Host).where(
            Host.engagement_id == scan.engagement_id,
            Host.ip == ip,
        )
    ).first()
    if host is None:
        host = Host(engagement_id=scan.engagement_id, ip=ip)
        session.add(host)
        session.flush()
    assert scan.id is not None and host.id is not None
    session.add(
        Observation(
            engagement_id=scan.engagement_id,
            scan_id=scan.id,
            host_id=host.id,
            port=port,
            proto=proto,
            state=state,
            service_name=service_name,
            product=product,
            version=version,
        )
    )


def test_diff_added_removed_changed(session: Session) -> None:
    a = ingest_scan(
        session, SCAN_A.encode(), "a.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )
    b = ingest_scan(
        session, SCAN_B.encode(), "b.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )
    assert a.id is not None and b.id is not None

    result = diff_scans(session, a.id, b.id, engagement_id=TEST_ENGAGEMENT_ID)
    by_port = {(e.port, e.kind): e for e in result.entries}

    # 443 appeared
    assert (443, "added") in by_port
    assert "nginx" in by_port[(443, "added")].after
    # 80 went open -> closed (state change is a "changed" entry, still present in both scans)
    assert (80, "changed") in by_port
    assert "open" in by_port[(80, "changed")].before
    assert "closed" in by_port[(80, "changed")].after
    # 22 version changed 8.9 -> 9.0
    assert (22, "changed") in by_port
    assert "8.9" in by_port[(22, "changed")].before
    assert "9.0" in by_port[(22, "changed")].after


@pytest.mark.parametrize(
    ("ports", "current_state"),
    [("", "open"), ('<extraports state="closed" count="1"/>', "closed")],
)
def test_snapshot_diff_does_not_inherit_replayed_port_evidence(
    session: Session,
    ports: str,
    current_state: str,
) -> None:
    baseline = (
        '<nmaprun start="100"><host><address addr="10.0.0.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.0"/></port></ports>'
        "</host></nmaprun>"
    ).encode()
    omitted = (
        '<nmaprun start="200"><scaninfo protocol="tcp" services="80" numservices="1"/>'
        '<host><address addr="10.0.0.1" addrtype="ipv4"/>'
        f"<ports>{ports}</ports></host></nmaprun>"
    ).encode()
    before = ingest_scan(
        session, baseline, "baseline.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )
    after = ingest_scan(
        session, omitted, "omitted.xml", "nmap", engagement_id=TEST_ENGAGEMENT_ID
    )
    assert before.id is not None and after.id is not None
    host = host_rows(session, engagement_id=TEST_ENGAGEMENT_ID)[0]
    _, latest = host_history(session, host.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert latest[(80, "tcp")].state == current_state

    # Snapshot comparison still reports absence, not an inferred closure or an
    # inherited open observation from a different scan.
    difference = diff_scans(
        session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID
    )
    assert [(entry.port, entry.proto, entry.kind) for entry in difference.entries] == [
        (80, "tcp", "removed"),
    ]
    reverse = diff_scans(session, after.id, before.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert [(entry.port, entry.proto, entry.kind) for entry in reverse.entries] == [
        (80, "tcp", "added"),
    ]


@pytest.mark.parametrize("per_page", [1, 3, 4])
def test_diff_pages_traverse_all_entries_in_stable_order(
    session: Session, per_page: int
) -> None:
    before = _scan(session, "before.xml")
    after = _scan(session, "after.xml")
    for ip, port, proto in [
        ("10.0.0.2", 80, "tcp"),
        ("10.0.0.10", 443, "tcp"),
        ("10.0.0.10", 22, "udp"),
        ("10.0.0.10", 22, "tcp"),
    ]:
        _observe(session, before, ip, port, proto)
    for ip, port, proto in [
        ("10.0.0.2", 80, "udp"),
        ("10.0.0.10", 8080, "tcp"),
        ("10.0.0.10", 21, "udp"),
        ("10.0.0.10", 21, "tcp"),
    ]:
        _observe(session, after, ip, port, proto)
    for ip, port in [
        ("10.0.0.2", 22),
        ("10.0.0.10", 10),
        ("10.0.0.10", 9),
    ]:
        _observe(session, before, ip, port, version="1")
        _observe(session, after, ip, port, version="2")
    for scan in (before, after):
        _observe(session, scan, "10.0.0.3", 53, "udp")
    session.commit()
    assert before.id is not None and after.id is not None

    expected = [
        ("added", "10.0.0.10", 21, "tcp"),
        ("added", "10.0.0.10", 21, "udp"),
        ("added", "10.0.0.10", 8080, "tcp"),
        ("added", "10.0.0.2", 80, "udp"),
        ("removed", "10.0.0.10", 22, "tcp"),
        ("removed", "10.0.0.10", 22, "udp"),
        ("removed", "10.0.0.10", 443, "tcp"),
        ("removed", "10.0.0.2", 80, "tcp"),
        ("changed", "10.0.0.10", 9, "tcp"),
        ("changed", "10.0.0.10", 10, "tcp"),
        ("changed", "10.0.0.2", 22, "tcp"),
    ]
    pages = (11 + per_page - 1) // per_page
    traversed = []
    for page in range(1, pages + 1):
        result = diff_scans(
            session,
            before.id,
            after.id,
            engagement_id=TEST_ENGAGEMENT_ID,
            page=page,
            per_page=per_page,
        )
        assert (result.total, result.page, result.pages) == (11, page, pages)
        assert result.scan_a.id == before.id
        assert result.scan_b.id == after.id
        keys = [(e.kind, e.ip, e.port, e.proto) for e in result.entries]
        assert keys == expected[(page - 1) * per_page : page * per_page]
        traversed.extend(keys)
        for entry in result.entries:
            if entry.kind == "added":
                assert (entry.before, entry.after) == (None, "open")
            elif entry.kind == "removed":
                assert (entry.before, entry.after) == ("open", None)
            else:
                assert (entry.before, entry.after) == ("open 1", "open 2")
    assert traversed == expected
    assert len(set(traversed)) == 11

    reverse = diff_scans(
        session,
        after.id,
        before.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        page=3,
        per_page=4,
    )
    assert (reverse.total, reverse.page, reverse.pages) == (11, 3, 3)
    assert [(e.kind, e.ip, e.port, e.proto) for e in reverse.entries] == expected[8:]
    assert [(e.before, e.after) for e in reverse.entries] == [
        ("open 2", "open 1"),
        ("open 2", "open 1"),
        ("open 2", "open 1"),
    ]
    reverse_first = diff_scans(
        session,
        after.id,
        before.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        per_page=4,
    )
    assert [(e.kind, e.ip, e.port, e.proto) for e in reverse_first.entries] == [
        ("added", "10.0.0.10", 22, "tcp"),
        ("added", "10.0.0.10", 22, "udp"),
        ("added", "10.0.0.10", 443, "tcp"),
        ("added", "10.0.0.2", 80, "tcp"),
    ]


def test_diff_defaults_clamps_pages_and_supports_all(session: Session) -> None:
    before = _scan(session, "empty.xml")
    after = _scan(session, "many.xml")
    for port in range(1, 32):
        _observe(session, after, "10.0.0.1", port)
    session.commit()
    assert before.id is not None and after.id is not None

    default = diff_scans(session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert (default.total, default.page, default.pages) == (31, 1, 2)
    assert [e.port for e in default.entries] == list(range(1, 26))

    first = diff_scans(
        session,
        before.id,
        after.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        page=-10,
        per_page=10,
    )
    assert (first.total, first.page, first.pages) == (31, 1, 4)
    assert [e.port for e in first.entries] == list(range(1, 11))
    last = diff_scans(
        session,
        before.id,
        after.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        page=999,
        per_page=10,
    )
    assert (last.total, last.page, last.pages) == (31, 4, 4)
    assert [e.port for e in last.entries] == [31]

    unlimited = diff_scans(
        session,
        before.id,
        after.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        page=999,
        per_page=None,
    )
    assert (unlimited.total, unlimited.page, unlimited.pages) == (31, 1, 1)
    assert [e.port for e in unlimited.entries] == list(range(1, 32))


@pytest.mark.parametrize("case", ["empty", "unchanged", "same-scan"])
@pytest.mark.parametrize("per_page", [3, None])
def test_empty_diff_has_one_clamped_page(
    session: Session, case: str, per_page: int | None
) -> None:
    before = _scan(session, "before.xml")
    after = before if case == "same-scan" else _scan(session, "after.xml")
    if case != "empty":
        _observe(session, before, "10.0.0.1", 22, version="1")
        if case == "unchanged":
            _observe(session, after, "10.0.0.1", 22, version="1")
    session.commit()
    assert before.id is not None and after.id is not None

    result = diff_scans(
        session,
        before.id,
        after.id,
        engagement_id=TEST_ENGAGEMENT_ID,
        page=99,
        per_page=per_page,
    )
    assert (result.total, result.page, result.pages) == (0, 1, 1)
    assert result.entries == []


@pytest.mark.parametrize(
    ("before_fields", "after_fields", "expected"),
    [
        ((None, None, None), ("", "", ""), None),
        (("http", "nginx 1", None), ("http", "nginx", "1"), None),
        (("http", "nginx", "1"), ("http nginx", None, "1"), None),
        ((None, "1", None), (None, None, "1"), None),
        ((" ", "\t", " "), (" ", "\t", " "), None),
        ((None, None, None), (" ", "", ""), ("open", "open  ")),
        ((None, None, " 1 "), (None, "", "1"), ("open  1 ", "open 1")),
        (
            (" http ", " nginx ", " 1 "),
            ("http", "nginx", "1"),
            ("open  http   nginx   1 ", "open http nginx 1"),
        ),
    ],
)
def test_diff_compares_formatted_summaries_without_normalizing_fields(
    session: Session,
    before_fields: tuple[str | None, str | None, str | None],
    after_fields: tuple[str | None, str | None, str | None],
    expected: tuple[str, str] | None,
) -> None:
    before = _scan(session, "before.xml")
    after = _scan(session, "after.xml")
    for scan, fields in [(before, before_fields), (after, after_fields)]:
        _observe(
            session,
            scan,
            "10.0.0.1",
            80,
            service_name=fields[0],
            product=fields[1],
            version=fields[2],
        )
    session.commit()
    assert before.id is not None and after.id is not None

    result = diff_scans(
        session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID, per_page=1
    )
    assert (result.page, result.pages) == (1, 1)
    if expected is None:
        assert result.total == 0
        assert result.entries == []
    else:
        assert result.total == 1
        assert [
            (entry.kind, entry.before, entry.after) for entry in result.entries
        ] == [("changed", *expected)]
        reverse = diff_scans(
            session, after.id, before.id, engagement_id=TEST_ENGAGEMENT_ID, per_page=1
        )
        assert reverse.total == 1
        assert [
            (entry.kind, entry.before, entry.after) for entry in reverse.entries
        ] == [("changed", expected[1], expected[0])]


@pytest.mark.parametrize(
    ("state", "summary"),
    [
        (ObsState.open, "open"),
        (ObsState.closed, "closed"),
        (ObsState.filtered, "filtered"),
        (ObsState.unfiltered, "unfiltered"),
        (ObsState.open_filtered, "open|filtered"),
        (ObsState.closed_filtered, "closed|filtered"),
    ],
)
def test_diff_summaries_use_observation_state_values(
    session: Session, state: ObsState, summary: str
) -> None:
    before = _scan(session, "empty.xml")
    after = _scan(session, "state.xml")
    _observe(session, after, "10.0.0.1", 80, state=state)
    session.commit()
    assert before.id is not None and after.id is not None

    added = diff_scans(session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert added.total == 1
    assert [(e.kind, e.before, e.after) for e in added.entries] == [
        ("added", None, summary)
    ]
    removed = diff_scans(session, after.id, before.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert removed.total == 1
    assert [(e.kind, e.before, e.after) for e in removed.entries] == [
        ("removed", summary, None)
    ]


def test_diff_keeps_last_observation_per_snapshot_key(session: Session) -> None:
    before = _scan(session, "before.xml")
    after = _scan(session, "after.xml")
    _observe(session, before, "10.0.0.1", 80, version="1")
    _observe(session, before, "10.0.0.1", 80, version="2")
    _observe(session, after, "10.0.0.1", 80, version="3")
    _observe(session, after, "10.0.0.1", 80, version="4")
    session.commit()
    assert before.id is not None and after.id is not None

    result = diff_scans(
        session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID, per_page=1
    )
    assert (result.total, result.page, result.pages) == (1, 1, 1)
    assert [(e.kind, e.before, e.after) for e in result.entries] == [
        ("changed", "open 2", "open 4")
    ]


def test_diff_enforces_engagement_ownership_before_comparison(session: Session) -> None:
    foreign_engagement_id = "foreign-diff-engagement"
    session.add(Engagement(id=foreign_engagement_id, name="Foreign engagement"))
    session.flush()
    before = _scan(session, "before.xml")
    after = _scan(session, "after.xml")
    foreign_before = _scan(
        session, "foreign-before.xml", engagement_id=foreign_engagement_id
    )
    foreign_after = _scan(
        session, "foreign-after.xml", engagement_id=foreign_engagement_id
    )
    _observe(session, after, "10.0.0.1", 80, version="local")
    _observe(session, foreign_before, "10.0.0.1", 80, version="foreign-before")
    _observe(session, foreign_after, "10.0.0.1", 80, version="foreign-after")
    _observe(session, foreign_after, "10.0.0.1", 443)
    session.commit()
    assert before.id is not None and after.id is not None
    assert foreign_before.id is not None and foreign_after.id is not None

    local = diff_scans(session, before.id, after.id, engagement_id=TEST_ENGAGEMENT_ID)
    assert local.total == 1
    assert [(e.ip, e.port, e.kind, e.after) for e in local.entries] == [
        ("10.0.0.1", 80, "added", "open local")
    ]
    for scan_a_id, scan_b_id in [
        (before.id, foreign_after.id),
        (foreign_before.id, after.id),
        (foreign_before.id, foreign_after.id),
        (foreign_before.id, foreign_before.id),
        (before.id, 999999),
        (999999, after.id),
        (999999, 999999),
    ]:
        with pytest.raises(ValueError, match="scan not found"):
            diff_scans(
                session,
                scan_a_id,
                scan_b_id,
                engagement_id=TEST_ENGAGEMENT_ID,
                page=99,
                per_page=1,
            )
    with pytest.raises(ValueError, match="scan not found"):
        diff_scans(session, before.id, after.id, engagement_id=foreign_engagement_id)
