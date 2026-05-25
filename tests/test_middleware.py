"""
Integration tests for RateLimitMiddleware and unit tests for IPExtractor.

The WSGI app under test is a minimal stub — no Flask dependency needed.
This keeps the tests fast and focused on middleware behaviour only.
"""

import json

import pytest

from middleware import IPExtractor, RateLimitMiddleware
from rate_limiter import RateLimitConfig, SlidingWindowRateLimiter


# ---------------------------------------------------------------------------
# WSGI test helpers
# ---------------------------------------------------------------------------

def _stub_app(environ, start_response):
    """Minimal WSGI app that always returns 200 OK."""
    start_response("200 OK", [("Content-Type", "application/json")])
    return [b'{"status": "ok"}']


def _make_environ(
    ip: str = "1.1.1.1",
    path: str = "/test",
    xff: str | None = None,
    x_real_ip: str | None = None,
) -> dict:
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "REMOTE_ADDR": ip}
    if xff:
        environ["HTTP_X_FORWARDED_FOR"] = xff
    if x_real_ip:
        environ["HTTP_X_REAL_IP"] = x_real_ip
    return environ


def _call(app, environ: dict) -> tuple[str, dict[str, str], bytes]:
    """Call a WSGI app and return (status, headers_dict, body)."""
    status_box: list[str] = []
    headers_box: list[tuple[str, str]] = []

    def start_response(status, headers, exc_info=None):
        status_box.append(status)
        headers_box.extend(headers)

    body = b"".join(app(environ, start_response))
    return status_box[0], dict(headers_box), body


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mw() -> RateLimitMiddleware:
    cfg = RateLimitConfig(
        max_requests=3,
        window_seconds=60.0,
        cleanup_interval=9999,
        max_ips=100,
    )
    return RateLimitMiddleware(_stub_app, SlidingWindowRateLimiter(cfg))


# ---------------------------------------------------------------------------
# Middleware — pass-through and 429
# ---------------------------------------------------------------------------

class TestPassThrough:

    def test_returns_200_within_limit(self, mw):
        status, _, _ = _call(mw, _make_environ())
        assert status.startswith("200")

    def test_returns_429_after_limit_exceeded(self, mw):
        env = _make_environ()
        for _ in range(3):
            _call(mw, env)
        status, _, _ = _call(mw, env)
        assert status.startswith("429")

    def test_body_429_is_valid_json(self, mw):
        env = _make_environ()
        for _ in range(3):
            _call(mw, env)
        _, _, body = _call(mw, env)
        data = json.loads(body)
        assert "error" in data
        assert "retry_after" in data

    def test_rate_limit_headers_present_on_200(self, mw):
        _, headers, _ = _call(mw, _make_environ())
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers

    def test_rate_limit_headers_present_on_429(self, mw):
        env = _make_environ()
        for _ in range(3):
            _call(mw, env)
        _, headers, _ = _call(mw, env)
        assert "X-RateLimit-Limit" in headers
        assert "Retry-After" in headers

    def test_content_type_on_429_includes_charset(self, mw):
        env = _make_environ()
        for _ in range(3):
            _call(mw, env)
        _, headers, _ = _call(mw, env)
        assert headers.get("Content-Type") == "application/json; charset=utf-8"

    def test_downstream_headers_are_preserved(self, mw):
        """Rate-limit headers must be appended, not replace downstream headers."""
        _, headers, _ = _call(mw, _make_environ())
        assert "Content-Type" in headers          # from _stub_app
        assert "X-RateLimit-Limit" in headers     # injected by middleware


# ---------------------------------------------------------------------------
# IP extraction — middleware integration
# ---------------------------------------------------------------------------

class TestIPExtractionIntegration:

    def test_xff_takes_priority_over_remote_addr(self, mw):
        """XFF IP and REMOTE_ADDR should be tracked as separate buckets."""
        env_a = _make_environ(ip="10.0.0.1", xff="203.0.113.10")
        env_b = _make_environ(ip="10.0.0.1", xff="203.0.113.20")

        for _ in range(3):
            _call(mw, env_a)

        status, _, _ = _call(mw, env_b)
        assert status.startswith("200"), "Different XFF IPs must have independent buckets"

    def test_xff_multi_value_uses_first_ip(self, mw):
        """X-Forwarded-For: client, proxy1, proxy2 — only the client IP counts."""
        # Exhaust limit for 1.2.3.4 via a multi-value XFF header.
        for _ in range(3):
            _call(mw, _make_environ(xff="1.2.3.4, 10.0.0.1"))
        status, _, _ = _call(mw, _make_environ(xff="1.2.3.4, 10.0.0.1"))
        assert status.startswith("429"), "1.2.3.4 should be rate limited"

        # The second IP (proxy) is a different key — must still be allowed.
        status, _, _ = _call(mw, _make_environ(xff="10.0.0.1"))
        assert status.startswith("200"), "Proxy IP should have its own independent bucket"

    def test_x_real_ip_used_when_xff_absent(self, mw):
        env_a = _make_environ(ip="10.0.0.1", x_real_ip="5.5.5.5")
        env_b = _make_environ(ip="10.0.0.1", x_real_ip="6.6.6.6")

        for _ in range(3):
            _call(mw, env_a)

        status, _, _ = _call(mw, env_b)
        assert status.startswith("200"), "Different X-Real-IP should be independent"

    def test_trust_proxy_false_ignores_xff(self):
        cfg = RateLimitConfig(max_requests=3, window_seconds=60.0,
                              cleanup_interval=9999, max_ips=100)
        mw = RateLimitMiddleware(_stub_app, SlidingWindowRateLimiter(cfg),
                                 trust_proxy=False)

        for _ in range(3):
            _call(mw, _make_environ(ip="9.9.9.9", xff="1.1.1.1"))

        # XFF is ignored: REMOTE_ADDR "9.9.9.9" is used for both requests.
        status, _, _ = _call(mw, _make_environ(ip="9.9.9.9", xff="2.2.2.2"))
        assert status.startswith("429"), "REMOTE_ADDR should be used when trust_proxy=False"


# ---------------------------------------------------------------------------
# IPExtractor — unit tests
# ---------------------------------------------------------------------------

class TestIPExtractor:

    def _env(self, ip="1.1.1.1", xff=None, x_real_ip=None):
        e = {"REMOTE_ADDR": ip}
        if xff:
            e["HTTP_X_FORWARDED_FOR"] = xff
        if x_real_ip:
            e["HTTP_X_REAL_IP"] = x_real_ip
        return e

    def test_remote_addr_returned_when_no_proxy_headers(self):
        ex = IPExtractor(trust_proxy=True)
        assert ex.extract(self._env(ip="1.2.3.4")) == "1.2.3.4"

    def test_xff_takes_priority(self):
        ex = IPExtractor(trust_proxy=True)
        assert ex.extract(self._env(xff="5.5.5.5")) == "5.5.5.5"

    def test_xff_multi_value_returns_first(self):
        ex = IPExtractor(trust_proxy=True)
        assert ex.extract(self._env(xff="1.1.1.1, 2.2.2.2, 3.3.3.3")) == "1.1.1.1"

    def test_xff_strips_whitespace(self):
        ex = IPExtractor(trust_proxy=True)
        assert ex.extract(self._env(xff="  9.9.9.9  ")) == "9.9.9.9"

    def test_x_real_ip_used_when_no_xff(self):
        ex = IPExtractor(trust_proxy=True)
        assert ex.extract(self._env(x_real_ip="7.7.7.7")) == "7.7.7.7"

    def test_xff_has_priority_over_x_real_ip(self):
        ex = IPExtractor(trust_proxy=True)
        assert ex.extract(self._env(xff="4.4.4.4", x_real_ip="8.8.8.8")) == "4.4.4.4"

    def test_trust_proxy_false_ignores_all_proxy_headers(self):
        ex = IPExtractor(trust_proxy=False)
        env = self._env(ip="9.9.9.9", xff="1.1.1.1", x_real_ip="2.2.2.2")
        assert ex.extract(env) == "9.9.9.9"

    def test_fallback_when_remote_addr_missing(self):
        ex = IPExtractor(trust_proxy=False)
        assert ex.extract({}) == "0.0.0.0"
