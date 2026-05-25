"""
WSGI Rate Limit Middleware
==========================
Drop-in wrapper for any WSGI application (Flask, Django, Falcon, etc.).

Usage:
    from rate_limiter import RateLimitConfig, SlidingWindowRateLimiter
    from middleware import RateLimitMiddleware

    limiter = SlidingWindowRateLimiter(RateLimitConfig(...))
    app.wsgi_app = RateLimitMiddleware(app.wsgi_app, limiter)
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Iterable

from rate_limiter import SlidingWindowRateLimiter

__all__ = ["IPExtractor", "RateLimitMiddleware"]

logger = logging.getLogger(__name__)

WSGIApp       = Callable[[dict, Callable], Iterable[bytes]]
StartResponse = Callable[..., None]

_FALLBACK_IP = "0.0.0.0"


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------

class IPExtractor:
    """
    Resolves the real client IP address from a WSGI environ dict.

    Trust chain, evaluated in priority order:
        1. X-Forwarded-For  — standard reverse-proxy header (Nginx, AWS ALB,
                               Cloudflare). The client IP is always the FIRST
                               value when the header contains a comma-separated
                               chain: "client, proxy1, proxy2".
        2. X-Real-IP        — simpler single-value header set by Nginx
                               proxy_pass with proxy_set_header X-Real-IP.
        3. REMOTE_ADDR      — the TCP peer address, always present. Used as
                               the fallback when trust_proxy is False or when
                               neither proxy header is present.

    Security note:
        Proxy headers are trivially forgeable by clients. Only set
        trust_proxy=True when your proxy is under your control AND is
        configured to *overwrite* (not merely append to) these headers.
    """

    def __init__(self, *, trust_proxy: bool = True) -> None:
        self._trust_proxy = trust_proxy

    def extract(self, environ: dict) -> str:
        if self._trust_proxy:
            xff = environ.get("HTTP_X_FORWARDED_FOR", "")
            if xff:
                return xff.split(",")[0].strip()

            x_real_ip = environ.get("HTTP_X_REAL_IP", "")
            if x_real_ip:
                return x_real_ip.strip()

        return environ.get("REMOTE_ADDR", _FALLBACK_IP)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware:
    """
    WSGI middleware that enforces rate limits before the request reaches
    the downstream application.

    Allowed requests pass through transparently with X-RateLimit-* headers
    injected into the response.

    Denied requests short-circuit with HTTP 429 and a JSON body containing
    `error`, `message`, and `retry_after` fields.
    """

    def __init__(
        self,
        app: WSGIApp,
        limiter: SlidingWindowRateLimiter,
        *,
        trust_proxy: bool = True,
    ) -> None:
        self._app = app
        self._limiter = limiter
        self._extractor = IPExtractor(trust_proxy=trust_proxy)

    def __call__(self, environ: dict, start_response: StartResponse) -> Iterable[bytes]:
        ip = self._extractor.extract(environ)
        result = self._limiter.is_allowed(ip)

        if result.allowed:
            wrapped = self._inject_headers(start_response, result.headers)
            return self._app(environ, wrapped)

        logger.warning("429 ip=%s path=%s", ip, environ.get("PATH_INFO", ""))
        return self._respond_429(start_response, result.headers)

    # ── Private ──────────────────────────────────────────────────────────────

    @staticmethod
    def _inject_headers(
        start_response: StartResponse,
        extra: dict[str, str],
    ) -> StartResponse:
        """Return a wrapped start_response that appends rate-limit headers."""
        def _wrapped(status: str, headers: list, exc_info=None):
            headers.extend(extra.items())
            return start_response(status, headers, exc_info)
        return _wrapped

    def _respond_429(
        self,
        start_response: StartResponse,
        rl_headers: dict[str, str],
    ) -> list[bytes]:
        s = self._limiter.stats()
        body = json.dumps(
            {
                "error": "Too Many Requests",
                "message": (
                    f"Limit of {s['max_requests']} requests "
                    f"per {s['window_seconds']}s exceeded."
                ),
                "retry_after": rl_headers.get("Retry-After"),
            },
            ensure_ascii=False,
        ).encode("utf-8")

        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            *list(rl_headers.items()),
        ]
        start_response("429 Too Many Requests", headers)
        return [body]
