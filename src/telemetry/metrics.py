"""
Prometheus metrics for QASP server observability.

This module defines metrics for monitoring QASP handshake performance, failures,
and key operations. Exposes a /metrics endpoint for Prometheus scraping.
"""

from prometheus_client import Counter, Histogram, CollectorRegistry, generate_latest
from prometheus_client.exposition import make_wsgi_app
import time

# Create a registry for our metrics
registry = CollectorRegistry()

# Handshake metrics
HANDSHAKE_DURATION = Histogram(
    'qasp_handshake_duration_seconds',
    'Duration of QASP handshake operations',
    ['operation'],
    registry=registry
)

HANDSHAKE_TOTAL = Counter(
    'qasp_handshakes_total',
    'Total number of QASP handshakes',
    ['result'],  # success, failure
    registry=registry
)

CHALLENGE_TOTAL = Counter(
    'qasp_challenges_total',
    'Total number of QASP challenge verifications',
    ['result'],  # success, failure
    registry=registry
)

RESOURCE_ACCESS_TOTAL = Counter(
    'qasp_resource_access_total',
    'Total number of protected resource accesses',
    ['result'],  # success, failure
    registry=registry
)

# Key management metrics
KEY_OPERATIONS_TOTAL = Counter(
    'qasp_key_operations_total',
    'Total number of key management operations',
    ['operation', 'result'],  # store, retrieve, list, rotate
    registry=registry
)


def get_metrics():
    """Get metrics data for Prometheus scraping."""
    return generate_latest(registry)


def make_metrics_app():
    """Create WSGI app for metrics endpoint."""
    return make_wsgi_app(registry=registry)


# Convenience functions for timing
class Timer:
    """Context manager for timing operations."""
    def __init__(self, histogram, labels):
        self.histogram = histogram
        self.labels = labels
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.histogram.labels(**self.labels).observe(duration)


def time_handshake(operation: str):
    """Decorator/context manager factory for timing handshakes."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            with Timer(HANDSHAKE_DURATION, {'operation': operation}):
                try:
                    result = await func(*args, **kwargs)
                    HANDSHAKE_TOTAL.labels(result='success').inc()
                    return result
                except Exception as e:
                    HANDSHAKE_TOTAL.labels(result='failure').inc()
                    raise
        return wrapper
    return decorator


# Export registry for external access
__all__ = [
    'registry', 'get_metrics', 'make_metrics_app',
    'HANDSHAKE_DURATION', 'HANDSHAKE_TOTAL', 'CHALLENGE_TOTAL', 'RESOURCE_ACCESS_TOTAL', 'KEY_OPERATIONS_TOTAL',
    'Timer', 'time_handshake'
]
