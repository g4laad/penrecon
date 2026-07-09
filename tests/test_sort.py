from __future__ import annotations

from penrecon.queries import HostRow, sort_hosts


def _row(ip: str, open_count: int = 0, status: str = "new") -> HostRow:
    return HostRow(
        id=0, ip=ip, hostnames=[], open_count=open_count, status=status,
        tags=[], open_ports=[], service_names=[], open_services=[],
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
