"""
Process-level DNS cache to reduce registry DNS lookups.

Patches socket.getaddrinfo with a TTL cache so repeated lookups for
the same hostname (auth.docker.io, ghcr.io, registry.theshellnet.com,
etc.) are served from memory instead of hitting the DNS server every time.

Cache entries expire after DNS_CACHE_TTL seconds (default 300 = 5 min),
so DNS changes propagate automatically without hardcoding IPs.

Import this module early (e.g. in __init__.py) to activate the cache.
"""

import os
import socket
import logging
import time
from threading import Lock

logger = logging.getLogger(__name__)

DNS_CACHE_TTL = int(os.environ.get("DNS_CACHE_TTL", "300"))

_cache: dict[tuple, tuple] = {}  # args -> (result, timestamp)
_lock = Lock()
_original_getaddrinfo = socket.getaddrinfo
_stats = {"hits": 0, "misses": 0}


def _cached_getaddrinfo(*args, **kwargs):
    """Drop-in replacement for socket.getaddrinfo with TTL caching."""
    # Only cache by the positional args (host, port, family, type, proto, flags)
    cache_key = args

    now = time.monotonic()

    with _lock:
        if cache_key in _cache:
            result, ts = _cache[cache_key]
            if now - ts < DNS_CACHE_TTL:
                _stats["hits"] += 1
                return result
            # Expired — fall through to resolve
            del _cache[cache_key]

    # Resolve via the real getaddrinfo
    result = _original_getaddrinfo(*args, **kwargs)

    with _lock:
        _cache[cache_key] = (result, now)
        _stats["misses"] += 1

    return result


def get_stats() -> dict:
    """Return cache hit/miss stats and entry count."""
    with _lock:
        return {
            "hits": _stats["hits"],
            "misses": _stats["misses"],
            "entries": len(_cache),
            "ttl_seconds": DNS_CACHE_TTL,
        }


def clear():
    """Flush the DNS cache."""
    with _lock:
        _cache.clear()
        _stats["hits"] = 0
        _stats["misses"] = 0


# Patch on import
socket.getaddrinfo = _cached_getaddrinfo
logger.info("DNS cache enabled (TTL=%ds)", DNS_CACHE_TTL)
