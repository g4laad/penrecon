from __future__ import annotations

from penrecon.queries import HostRow, filter_hosts, paginate, sort_hosts


def _row(ip: str, open_count: int = 0, status: str = "new", change: str = "") -> HostRow:
    return HostRow(
        id=0, ip=ip, hostnames=[], open_count=open_count, status=status,
        tags=[], open_ports=[], service_names=[], open_services=[], change=change,
    )


def test_ip_sort_respects_direction() -> None:
    rows = [_row("10.0.0.2"), _row("10.0.0.10"), _row("10.0.0.1")]
    asc = [r.ip for r in sort_hosts(rows, "ip", "asc")]
    assert asc == ["10.0.0.1", "10.0.0.2", "10.0.0.10"]  # numeric, not lexical
    assert [r.ip for r in sort_hosts(rows, "ip", "desc")] == list(reversed(asc))


def test_ports_sort_direction() -> None:
    rows = [_row("a", 1), _row("b", 9), _row("c", 3)]
    assert [r.open_count for r in sort_hosts(rows, "ports", "desc")] == [9, 3, 1]
    assert [r.open_count for r in sort_hosts(rows, "ports", "asc")] == [1, 3, 9]


def test_change_sort_groups_new_then_changed_then_unchanged_ports_desc() -> None:
    rows = [
        _row("10.0.0.1", 9, change=""),        # unchanged, most open
        _row("10.0.0.2", 2, change="new"),     # new, few open
        _row("10.0.0.3", 5, change="changed"),
        _row("10.0.0.4", 7, change="new"),     # new, more open -> before .2
        _row("10.0.0.5", 1, change=""),
    ]
    # new (ports desc) -> changed -> unchanged (ports desc)
    assert [r.ip for r in sort_hosts(rows, "change", "asc")] == \
        ["10.0.0.4", "10.0.0.2", "10.0.0.3", "10.0.0.1", "10.0.0.5"]
    # desc reverses the change groups
    assert [r.change for r in sort_hosts(rows, "change", "desc")][:1] == [""]


def test_filter_by_change() -> None:
    rows = [_row("10.0.0.1", change="new"), _row("10.0.0.2", change="changed"),
            _row("10.0.0.3", change="")]
    assert [r.ip for r in filter_hosts(rows, change="new")] == ["10.0.0.1"]
    assert [r.ip for r in filter_hosts(rows, change="changed")] == ["10.0.0.2"]
    assert [r.ip for r in filter_hosts(rows, change="unchanged")] == ["10.0.0.3"]  # "" state
    assert len(filter_hosts(rows, change="")) == 3  # "any" is a no-op


def test_paginate_slices_and_clamps() -> None:
    rows = [_row(f"10.0.0.{i}") for i in range(1, 26)]  # 25 rows
    page_rows, page, pages = paginate(rows, page=1, per_page=10)
    assert (len(page_rows), page, pages) == (10, 1, 3)
    assert paginate(rows, page=3, per_page=10)[0][-1].ip == "10.0.0.25"  # last page, 5 rows
    assert len(paginate(rows, page=3, per_page=10)[0]) == 5
    # out-of-range page clamps to the last real page, never an empty slice
    assert paginate(rows, page=99, per_page=10)[1] == 3
    # empty input still yields one (empty) page, not zero
    assert paginate([], page=1, per_page=10) == ([], 1, 1)
