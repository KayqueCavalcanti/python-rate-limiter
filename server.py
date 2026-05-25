from __future__ import annotations

import time

from flask import Flask, jsonify

from middleware import RateLimitMiddleware
from rate_limiter import RateLimitConfig, SlidingWindowRateLimiter

app = Flask(__name__)
app.json.ensure_ascii = False

_SERVER_START = time.monotonic()

_LIMITER = SlidingWindowRateLimiter(RateLimitConfig(
    max_requests=5,
    window_seconds=10,
    cleanup_interval=60,
    max_ips=10_000,
))

app.wsgi_app = RateLimitMiddleware(app.wsgi_app, _LIMITER)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/hello")
def hello():
    return jsonify({"msg": "ok"})


@app.route("/stats")
def stats():
    """
    Internal metrics endpoint. Protect with authentication or IP allowlist
    before exposing in production.
    """
    s = _LIMITER.stats()
    return jsonify({
        "uptime_seconds": round(time.monotonic() - _SERVER_START, 2),
        "tracked_ips":    s["tracked_ips"],
        "max_ips_cap":    s["max_ips_cap"],
        "config": {
            "max_requests":   s["max_requests"],
            "window_seconds": s["window_seconds"],
        },
    })


if __name__ == "__main__":
    app.run(port=5000)
