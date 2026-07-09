from __future__ import annotations

from penrecon.web.app import _normalize_ip


def test_normalize_ip_accepts_and_canonicalizes() -> None:
    assert _normalize_ip("10.0.0.5") == "10.0.0.5"
    assert _normalize_ip("  192.168.1.1  ") == "192.168.1.1"  # trims
    assert _normalize_ip("2001:0DB8::0001") == "2001:db8::1"  # canonical IPv6
    assert _normalize_ip("::1") == "::1"


def test_normalize_ip_rejects_non_ip() -> None:
    for bad in ["", "not-an-ip", "10.0.0.256", "10.0.0", "1.2.3.4.5",
                "10.0.0.01", "gw.internal", "1234::xyz"]:
        assert _normalize_ip(bad) is None, bad
