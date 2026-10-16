from __future__ import annotations

import socket

import pytest

from windows_mcp.infrastructure import validate_url


def _addrinfo(ip: str, port: int) -> list[tuple]:
    if ":" in ip:
        sockaddr = (ip, port, 0, 0)
        family = socket.AF_INET6
    else:
        sockaddr = (ip, port)
        family = socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


@pytest.mark.parametrize("ip", ["198.18.1.238", "2001:2::123"])
def test_fake_ip_dns_ranges_get_actionable_diagnostic(monkeypatch, ip: str) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, **kwargs: _addrinfo(ip, port or 443),
    )

    with pytest.raises(ValueError) as exc_info:
        validate_url("https://public.example/page")

    message = str(exc_info.value)
    assert "public.example" in message
    assert ip in message
    assert "Fake-IP DNS" in message
    assert "blocked by SSRF protection" in message
    assert "Fake-IP exclusion list" in message


def test_literal_benchmark_ip_keeps_generic_ssrf_error(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, **kwargs: _addrinfo("198.18.1.238", port or 80),
    )

    with pytest.raises(ValueError) as exc_info:
        validate_url("http://198.18.1.238/")

    message = str(exc_info.value)
    assert "Private, loopback, link-local, multicast, and reserved addresses are blocked" in message
    assert "Fake-IP DNS" not in message


def test_ordinary_private_dns_keeps_generic_ssrf_error(monkeypatch) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, **kwargs: _addrinfo("10.0.0.5", port or 443),
    )

    with pytest.raises(ValueError) as exc_info:
        validate_url("https://internal-looking.example/")

    message = str(exc_info.value)
    assert "Private, loopback, link-local, multicast, and reserved addresses are blocked" in message
    assert "Fake-IP DNS" not in message
