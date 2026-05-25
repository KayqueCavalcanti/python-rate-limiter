"""
Unit tests for SlidingWindowRateLimiter.

Coverage:
    - Basic allow / deny behaviour
    - HTTP response headers
    - IP isolation
    - Window expiration and partial-window counts
    - Concurrency — race conditions under threading.Barrier
    - Memory — IP cap and stale-IP eviction
    - Config validation
"""

import threading
import time

import pytest

from rate_limiter import RateLimitConfig, SlidingWindowRateLimiter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_limiter(**overrides) -> SlidingWindowRateLimiter:
    """Build a limiter with sensible test defaults, overridable per-test."""
    defaults = dict(
        max_requests=10,
        window_seconds=60.0,
        cleanup_interval=9999,
        max_ips=100,
    )
    return SlidingWindowRateLimiter(RateLimitConfig(**{**defaults, **overrides}))


# ---------------------------------------------------------------------------
# Basic behaviour
# ---------------------------------------------------------------------------

class TestAllow:

    def test_permits_requests_within_limit(self, limiter):
        for _ in range(5):
            result = limiter.is_allowed("1.1.1.1")
            assert result.allowed

    def test_blocks_request_over_limit(self, limiter):
        for _ in range(5):
            limiter.is_allowed("1.1.1.1")
        assert not limiter.is_allowed("1.1.1.1").allowed

    def test_ip_isolation(self, limiter):
        for _ in range(5):
            limiter.is_allowed("1.1.1.1")
        assert limiter.is_allowed("2.2.2.2").allowed

    @pytest.mark.slow
    def test_allows_again_after_window_expires(self, limiter):
        for _ in range(5):
            limiter.is_allowed("1.1.1.1")
        time.sleep(1.1)
        assert limiter.is_allowed("1.1.1.1").allowed

    @pytest.mark.slow
    def test_expired_requests_do_not_count(self, limiter):
        """Timestamps from a previous window must not consume slots in the next."""
        for _ in range(3):
            limiter.is_allowed("1.1.1.1")
        time.sleep(1.1)
        for _ in range(5):
            assert limiter.is_allowed("1.1.1.1").allowed


# ---------------------------------------------------------------------------
# Response headers
# ---------------------------------------------------------------------------

class TestHeaders:

    def test_remaining_decrements_each_request(self, limiter):
        for i in range(5):
            headers = limiter.is_allowed("1.1.1.1").headers
            assert headers["X-RateLimit-Remaining"] == str(4 - i)

    def test_limit_header_matches_config(self, limiter):
        headers = limiter.is_allowed("1.1.1.1").headers
        assert headers["X-RateLimit-Limit"] == "5"

    def test_reset_header_is_positive(self, limiter):
        headers = limiter.is_allowed("1.1.1.1").headers
        assert float(headers["X-RateLimit-Reset"]) > 0

    def test_retry_after_present_when_denied(self, limiter):
        for _ in range(5):
            limiter.is_allowed("1.1.1.1")
        headers = limiter.is_allowed("1.1.1.1").headers
        assert "Retry-After" in headers
        assert int(headers["Retry-After"]) >= 1

    def test_retry_after_absent_when_allowed(self, limiter):
        headers = limiter.is_allowed("1.1.1.1").headers
        assert "Retry-After" not in headers

    def test_remaining_is_zero_on_last_allowed_request(self, limiter):
        for _ in range(4):
            limiter.is_allowed("1.1.1.1")
        headers = limiter.is_allowed("1.1.1.1").headers  # 5th — last allowed
        assert headers["X-RateLimit-Remaining"] == "0"


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

class TestConcurrency:

    def test_no_race_condition_same_ip(self):
        """
        50 threads fire simultaneously at limit=10. Without a per-IP lock,
        multiple threads would read count < 10 and all proceed, exceeding
        the limit. With the lock, exactly 10 pass through.
        """
        lim = _make_limiter(max_requests=10, window_seconds=60.0)

        results: list[bool] = []
        collector_lock = threading.Lock()
        barrier = threading.Barrier(50)

        def worker():
            barrier.wait()
            allowed = lim.is_allowed("10.0.0.1").allowed
            with collector_lock:
                results.append(allowed)

        threads = [threading.Thread(target=worker) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 10, (
            f"Expected exactly 10 allowed, got {sum(results)}"
        )

    def test_distinct_ips_do_not_block_each_other(self):
        """Each IP has its own bucket — parallel requests from different IPs
        must not interfere with one another."""
        lim = _make_limiter(max_requests=1, window_seconds=60.0, max_ips=200)

        results: dict[str, bool] = {}
        collector_lock = threading.Lock()
        barrier = threading.Barrier(100)

        def worker(ip: str):
            barrier.wait()
            allowed = lim.is_allowed(ip).allowed
            with collector_lock:
                results[ip] = allowed

        threads = [
            threading.Thread(target=worker, args=(f"10.0.0.{i}",))
            for i in range(100)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results.values()), "Distinct IPs should not block each other"


# ---------------------------------------------------------------------------
# Memory management
# ---------------------------------------------------------------------------

class TestMemory:

    def test_ip_cap_is_never_exceeded(self):
        lim = _make_limiter(max_ips=50, window_seconds=60.0)

        for i in range(300):
            lim.is_allowed(f"10.{i // 256}.{i % 256}.1")

        tracked = lim.stats()["tracked_ips"]
        assert tracked <= 50, f"Dict exceeded cap: {tracked} entries"

    @pytest.mark.slow
    def test_flush_stale_removes_idle_ips(self):
        lim = _make_limiter(window_seconds=0.3)

        for i in range(10):
            lim.is_allowed(f"10.0.0.{i}")

        assert lim.stats()["tracked_ips"] == 10

        time.sleep(0.7)  # wait for 2× the window (grace period)
        removed = lim.flush_stale()

        assert removed == 10
        assert lim.stats()["tracked_ips"] == 0

    @pytest.mark.slow
    def test_active_ip_survives_flush(self):
        lim = _make_limiter(window_seconds=0.3)

        lim.is_allowed("192.168.1.1")   # active IP
        lim.is_allowed("10.0.0.1")      # IP that will go idle

        time.sleep(0.7)
        lim.is_allowed("192.168.1.1")   # refresh last_seen

        lim.flush_stale()

        assert lim.stats()["tracked_ips"] == 1

    def test_stats_tracked_ips_increments_on_new_ip(self):
        lim = _make_limiter()
        assert lim.stats()["tracked_ips"] == 0
        lim.is_allowed("1.1.1.1")
        assert lim.stats()["tracked_ips"] == 1
        lim.is_allowed("2.2.2.2")
        assert lim.stats()["tracked_ips"] == 2


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

class TestConfig:

    @pytest.mark.parametrize("field,value", [
        ("max_requests", 0),
        ("max_requests", -1),
        ("window_seconds", 0),
        ("window_seconds", -5.0),
        ("max_ips", 0),
        ("max_ips", -100),
    ])
    def test_invalid_config_raises(self, field, value):
        kwargs = dict(max_requests=10, window_seconds=1.0,
                      cleanup_interval=60, max_ips=100)
        kwargs[field] = value
        with pytest.raises(ValueError, match=field):
            RateLimitConfig(**kwargs)

    def test_stats_contains_expected_keys(self, limiter):
        s = limiter.stats()
        assert {"tracked_ips", "max_ips_cap", "max_requests", "window_seconds"} <= s.keys()
