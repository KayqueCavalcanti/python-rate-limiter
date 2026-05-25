import pytest

from rate_limiter import RateLimitConfig, SlidingWindowRateLimiter


@pytest.fixture
def config():
    """Default config: 5 requests per 1-second window, daemon disabled."""
    return RateLimitConfig(
        max_requests=5,
        window_seconds=1.0,
        cleanup_interval=9999,
        max_ips=100,
    )


@pytest.fixture
def limiter(config):
    return SlidingWindowRateLimiter(config)
