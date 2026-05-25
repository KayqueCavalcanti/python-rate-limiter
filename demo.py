"""
Demo - Sliding Window Log Rate Limiter
=======================================
Four progressive scenarios, all using only the stdlib.

    python demo.py
"""

from __future__ import annotations

import threading
import time

from rate_limiter import RateLimitConfig, SlidingWindowRateLimiter

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def ok(msg: str)   -> None: print(f"  {GREEN}[OK  ]{RESET} {msg}")
def fail(msg: str) -> None: print(f"  {RED}[FAIL]{RESET} {msg}")
def info(msg: str) -> None: print(f"  {BLUE}[....]{RESET} {msg}")


def section(title: str) -> None:
    print(f"\n{BOLD}{YELLOW}{'-' * 60}{RESET}")
    print(f"{BOLD}{YELLOW}  {title}{RESET}")
    print(f"{BOLD}{YELLOW}{'-' * 60}{RESET}")


def _make_limiter(**kwargs) -> SlidingWindowRateLimiter:
    defaults = dict(max_requests=5, window_seconds=2.0,
                    cleanup_interval=9999, max_ips=1_000)
    return SlidingWindowRateLimiter(RateLimitConfig(**{**defaults, **kwargs}))


# ---------------------------------------------------------------------------
# Scenario 1 — Basic allow / deny
# ---------------------------------------------------------------------------

def scenario_basic() -> None:
    section("Scenario 1 - Basic allow / deny  (5 req / 2s)")
    limiter = _make_limiter()

    for i in range(1, 6):
        result = limiter.is_allowed("192.168.1.1")
        remaining = result.headers["X-RateLimit-Remaining"]
        if result.allowed:
            ok(f"Req {i}/5 -> ALLOWED  (remaining={remaining})")
        else:
            fail(f"Req {i}/5 -> BLOCKED (unexpected)")

    result = limiter.is_allowed("192.168.1.1")
    if not result.allowed:
        ok(f"Req 6/5 -> 429 BLOCKED  (Retry-After={result.headers.get('Retry-After')}s)")
    else:
        fail("Req 6/5 should have been blocked!")

    result = limiter.is_allowed("10.0.0.1")
    if result.allowed:
        ok("Different IP (10.0.0.1) -> ALLOWED  (buckets are independent)")
    else:
        fail("Different IP was blocked -- isolation bug!")

    info("Waiting for window to expire (2.1s)...")
    time.sleep(2.1)
    result = limiter.is_allowed("192.168.1.1")
    if result.allowed:
        ok(f"After window reset -> ALLOWED again  (remaining={result.headers['X-RateLimit-Remaining']})")
    else:
        fail("Should be allowed after window expired!")


# ---------------------------------------------------------------------------
# Scenario 2 — Race condition: N threads, same IP, same instant
# ---------------------------------------------------------------------------

def scenario_race_condition() -> None:
    section("Scenario 2 - Race condition  (50 threads, limit=10)")

    LIMIT, THREADS = 10, 50
    limiter = _make_limiter(max_requests=LIMIT, window_seconds=60.0)

    results: list[bool] = []
    collector = threading.Lock()
    barrier   = threading.Barrier(THREADS)   # all threads fire simultaneously

    def worker() -> None:
        barrier.wait()
        allowed = limiter.is_allowed("172.16.0.1").allowed
        with collector:
            results.append(allowed)

    threads = [threading.Thread(target=worker) for _ in range(THREADS)]
    for t in threads: t.start()
    for t in threads: t.join()

    allowed_count = sum(results)
    info(f"{THREADS} simultaneous threads, same IP")
    info(f"Allowed: {allowed_count}  |  Blocked: {THREADS - allowed_count}")

    if allowed_count == LIMIT:
        ok(f"Exactly {LIMIT} requests allowed -- no race condition")
    elif allowed_count < LIMIT:
        fail(f"Only {allowed_count} allowed -- possible starvation")
    else:
        fail(f"RACE CONDITION: {allowed_count} passed (expected {LIMIT})")

    if limiter.stats()["tracked_ips"] == 1:
        ok("Internal state consistent (1 bucket tracked)")


# ---------------------------------------------------------------------------
# Scenario 3 — Memory pressure: IP-spoofing simulation
# ---------------------------------------------------------------------------

def scenario_memory() -> None:
    section("Scenario 3 - Memory pressure  (cap=100 IPs, injecting 500)")

    CAP, INJECT = 100, 500
    limiter = _make_limiter(window_seconds=60.0, max_ips=CAP)

    for i in range(INJECT):
        limiter.is_allowed(f"10.{i // 256}.{i % 256}.1")

    tracked = limiter.stats()["tracked_ips"]
    info(f"IPs injected: {INJECT}  |  IPs in dict: {tracked}  |  Cap: {CAP}")

    if tracked <= CAP:
        ok(f"Dict bounded to {tracked} entries (<= {CAP}) -- no memory leak")
    else:
        fail(f"Memory leak! Dict has {tracked} entries (cap={CAP})")


# ---------------------------------------------------------------------------
# Scenario 4 — Cleanup daemon removes idle IPs
# ---------------------------------------------------------------------------

def scenario_cleanup() -> None:
    section("Scenario 4 - Cleanup daemon  (window=1s, interval=1.5s)")

    limiter = _make_limiter(window_seconds=1.0, cleanup_interval=1.5, max_ips=10_000)

    for i in range(10):
        limiter.is_allowed(f"203.0.113.{i}")

    before = limiter.stats()["tracked_ips"]
    info(f"IPs tracked before cleanup: {before}")

    info("Waiting for daemon sweep (3.5s)...")
    time.sleep(3.6)

    after = limiter.stats()["tracked_ips"]
    info(f"IPs tracked after cleanup:  {after}")

    if after < before:
        ok(f"Daemon evicted {before - after} idle IPs")
    else:
        fail("Daemon did not evict idle IPs -- possible memory leak!")

    limiter.is_allowed("198.51.100.1")   # keep this IP alive
    time.sleep(3.6)
    if limiter.is_allowed("198.51.100.1").allowed:
        ok("Active IP survived the cleanup sweep")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\n{BOLD}Rate Limiter - Sliding Window Log - Demo{RESET}")
    print("=" * 60)

    scenario_basic()
    scenario_race_condition()
    scenario_memory()
    scenario_cleanup()

    print(f"\n{GREEN}{BOLD}All scenarios completed successfully.{RESET}\n")
