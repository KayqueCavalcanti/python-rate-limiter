"""
Sliding Window Log Rate Limiter
================================
Implements per-IP request rate limiting using the Sliding Window Log algorithm.

Why Sliding Window Log over Token Bucket?
    Token Bucket allows a "boundary burst": a client can consume a full burst
    just before the window resets and another full burst right after, effectively
    doubling throughput at the boundary. Sliding Window Log ties every request to
    a real timestamp, eliminating that artifact — critical for auth and payment APIs.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

__all__ = ["RateLimitConfig", "RateLimitResult", "SlidingWindowRateLimiter"]

logger = logging.getLogger(__name__)

# IPs that have been idle for more than this many windows are evicted from memory.
_STALE_GRACE_FACTOR = 2


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RateLimitConfig:
    """
    Immutable rate limiter configuration.

    frozen=True prevents accidental mutation at runtime, which would
    cause race conditions between the cleanup daemon and HTTP workers.
    """

    max_requests: int       # maximum requests allowed within the window
    window_seconds: float   # sliding window duration in seconds
    cleanup_interval: float # how often the background daemon sweeps stale IPs
    max_ips: int            # hard cap on tracked IPs — protects RAM under IP-spoofing

    def __post_init__(self) -> None:
        if self.max_requests <= 0:
            raise ValueError(f"max_requests must be > 0, got {self.max_requests}")
        if self.window_seconds <= 0:
            raise ValueError(f"window_seconds must be > 0, got {self.window_seconds}")
        if self.max_ips <= 0:
            raise ValueError(f"max_ips must be > 0, got {self.max_ips}")


class RateLimitResult(NamedTuple):
    """
    Result of a single rate-limit check.

    Using NamedTuple allows both attribute access (result.allowed) and
    tuple unpacking (allowed, headers = limiter.is_allowed(ip)).
    """

    allowed: bool
    headers: dict[str, str]


# ---------------------------------------------------------------------------
# Internal state
# ---------------------------------------------------------------------------

@dataclass
class _Bucket:
    """
    Sliding window state for a single IP address.

    The IP itself is the dict key; this object holds only the timestamps
    and the synchronisation primitive.

    Space: O(max_requests) — the deque maxlen prevents unbounded growth
    even under burst traffic (Python discards the oldest entry on append
    when the deque is full).
    """

    timestamps: deque
    lock: threading.Lock
    last_seen: float

    @classmethod
    def new(cls, max_requests: int) -> _Bucket:
        return cls(
            timestamps=deque(maxlen=max_requests),
            lock=threading.Lock(),
            last_seen=time.monotonic(),
        )


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    """
    Thread-safe rate limiter — Sliding Window Log algorithm.

    Complexity
    ----------
    is_allowed : O(K) amortised, K = expired timestamps evicted this call.
                 In steady state K << max_requests, making it effectively O(1).
    Memory     : O(I * R) total, I = active IPs, R = max_requests each.
                 Bounded by the max_ips cap enforced via LRU eviction.

    Two-level locking (strict acquisition order prevents deadlock)
    -------------------------------------------------------------
    Level 1 — _global_lock  : guards the _buckets dict (insert / delete).
    Level 2 — bucket.lock   : guards a single bucket's timestamp deque.

    Rule: always acquire _global_lock BEFORE bucket.lock. Never reverse.
    """

    def __init__(self, config: RateLimitConfig) -> None:
        self._cfg = config
        self._buckets: dict[str, _Bucket] = {}
        self._global_lock = threading.Lock()
        self._start_cleanup_daemon()

    # ── Public API ───────────────────────────────────────────────────────────

    def is_allowed(self, ip: str) -> RateLimitResult:
        """
        Check whether a request from `ip` is within the rate limit.

        Sliding Window Log — three steps inside the per-IP lock:
          1. Evict timestamps older than window_start.        O(K)
          2. Count remaining timestamps.                      O(1)
          3. Allow and record if below limit; deny otherwise. O(1)
        """
        now = time.monotonic()
        bucket = self._get_or_create(ip)

        with bucket.lock:
            bucket.last_seen = now
            window_start = now - self._cfg.window_seconds

            while bucket.timestamps and bucket.timestamps[0] < window_start:
                bucket.timestamps.popleft()

            count = len(bucket.timestamps)
            remaining = self._cfg.max_requests - count

            if remaining > 0:
                bucket.timestamps.append(now)
                return RateLimitResult(
                    allowed=True,
                    headers=self._make_response_headers(
                        remaining=remaining - 1,
                        reset_in=self._cfg.window_seconds,
                    ),
                )

            # The oldest timestamp tells us exactly when a slot will free up.
            retry_after = bucket.timestamps[0] + self._cfg.window_seconds - now
            logger.warning("rate_limit_exceeded ip=%s retry_after=%.2fs", ip, retry_after)
            return RateLimitResult(
                allowed=False,
                headers=self._make_response_headers(
                    remaining=0,
                    reset_in=retry_after,
                    retry_after=retry_after,
                ),
            )

    def stats(self) -> dict[str, object]:
        """Return a metrics snapshot suitable for dashboards or /stats endpoints."""
        with self._global_lock:
            return {
                "tracked_ips":   len(self._buckets),
                "max_ips_cap":   self._cfg.max_ips,
                "max_requests":  self._cfg.max_requests,
                "window_seconds": self._cfg.window_seconds,
            }

    def flush_stale(self) -> int:
        """
        Manually trigger stale-IP eviction and return the count removed.
        Intended for testing; the daemon calls this automatically in production.
        """
        return self._evict_stale_ips()

    # ── Private ──────────────────────────────────────────────────────────────

    def _get_or_create(self, ip: str) -> _Bucket:
        """
        Return the bucket for `ip`, creating it if absent.

        Uses double-checked locking: a fast unsynchronised read on the hot
        path (> 99 % of calls), and a full lock only when inserting a new IP.

        Note on the GIL: CPython's GIL makes the unsynchronised dict read
        safe from memory corruption, but the "check then insert" logic still
        requires the lock for semantic correctness — and on free-threaded
        runtimes (Python 3.13+, PyPy) the lock is essential for safety.
        """
        bucket = self._buckets.get(ip)
        if bucket is not None:
            return bucket

        with self._global_lock:
            bucket = self._buckets.get(ip)  # re-check after acquiring lock
            if bucket is not None:
                return bucket

            if len(self._buckets) >= self._cfg.max_ips:
                self._evict_lru_under_lock()

            bucket = _Bucket.new(self._cfg.max_requests)
            self._buckets[ip] = bucket
            return bucket

    def _evict_lru_under_lock(self) -> None:
        """
        Remove the least-recently-used IP. Caller must hold _global_lock.

        O(I) linear scan — acceptable because evictions only happen when the
        dict reaches capacity, which in normal traffic never occurs. Under an
        IP-spoofing attack the O(I) cost is dominated by the attack itself.
        """
        lru_ip = min(self._buckets, key=lambda k: self._buckets[k].last_seen)
        del self._buckets[lru_ip]
        logger.warning("eviction_lru ip=%s cap=%d", lru_ip, self._cfg.max_ips)

    def _evict_stale_ips(self) -> int:
        """
        Remove IPs idle for more than _STALE_GRACE_FACTOR windows.

        The grace factor (2×) ensures that an IP whose last request landed
        just before the sweep always has its deque expire before it is
        removed — preventing a live IP from losing its window state.

        O(I) scan; runs under _global_lock to be atomic with dict mutations.
        """
        cutoff = time.monotonic() - self._cfg.window_seconds * _STALE_GRACE_FACTOR

        with self._global_lock:
            stale = [ip for ip, b in self._buckets.items() if b.last_seen < cutoff]
            for ip in stale:
                del self._buckets[ip]

        if stale:
            logger.info("cleanup evicted=%d stale IPs", len(stale))
        return len(stale)

    def _start_cleanup_daemon(self) -> None:
        def _loop() -> None:
            while True:
                time.sleep(self._cfg.cleanup_interval)
                try:
                    self._evict_stale_ips()
                except Exception:
                    logger.exception("error in rate limiter cleanup thread")

        thread = threading.Thread(target=_loop, name="ratelimiter-cleanup", daemon=True)
        thread.start()

    def _make_response_headers(
        self,
        remaining: int,
        reset_in: float,
        retry_after: float | None = None,
    ) -> dict[str, str]:
        """
        Build standard rate-limit HTTP response headers.

        X-RateLimit-Limit:     maximum requests in the window
        X-RateLimit-Remaining: slots remaining in this window
        X-RateLimit-Reset:     seconds until the window resets
        Retry-After:           (429 only) seconds the client should wait
        """
        headers: dict[str, str] = {
            "X-RateLimit-Limit":     str(self._cfg.max_requests),
            "X-RateLimit-Remaining": str(max(remaining, 0)),
            "X-RateLimit-Reset":     f"{reset_in:.2f}",
        }
        if retry_after is not None:
            # Round up so the client never retries before the slot is free.
            headers["Retry-After"] = str(int(retry_after) + 1)
        return headers
