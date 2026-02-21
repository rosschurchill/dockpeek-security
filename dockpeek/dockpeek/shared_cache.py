"""
Generic file-based cache for multi-worker compatibility.

Uses fcntl locking for atomic reads and writes across multiple
Gunicorn worker processes. All workers can read/write the same
cache file safely.
"""

import os
import json
import fcntl
import logging
from pathlib import Path
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional, Dict, Any, Callable, Tuple, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')


class FileBasedCache:
    """
    Thread-safe, multi-worker-safe file-based cache.

    Uses fcntl file locking for cross-process synchronization:
    - LOCK_SH (shared) for reads - multiple readers allowed
    - LOCK_EX (exclusive) for writes - single writer only

    Each cache entry stores (data, timestamp) for expiration checking.
    """

    def __init__(
        self,
        cache_file: str,
        duration_seconds: int = 3600,
        serializer: Optional[Callable[[Any], Dict]] = None,
        deserializer: Optional[Callable[[Dict], Any]] = None
    ):
        """
        Initialize the file-based cache.

        Args:
            cache_file: Path to the JSON cache file
            duration_seconds: How long entries remain valid (default 1 hour)
            serializer: Optional function to convert objects to JSON-compatible dicts
            deserializer: Optional function to convert dicts back to objects
        """
        self._cache_file = Path(cache_file)
        self._duration = duration_seconds
        self._local_lock = Lock()  # For thread safety within process
        self._serializer = serializer or (lambda x: x)
        self._deserializer = deserializer or (lambda x: x)

    def _read_cache(self) -> Dict[str, Any]:
        """Read entire cache file with shared lock."""
        if not self._cache_file.exists():
            return {}
        try:
            with open(self._cache_file, 'r') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    content = f.read()
                    if not content.strip():
                        return {}
                    return json.loads(content)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except (json.JSONDecodeError, IOError) as e:
            logger.debug(f"Failed to read cache {self._cache_file}: {e}")
            return {}

    def _write_cache(self, cache: Dict[str, Any]) -> None:
        """Write entire cache file with exclusive lock."""
        try:
            # Ensure directory exists
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    json.dump(cache, f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except IOError as e:
            logger.warning(f"Failed to write cache {self._cache_file}: {e}")

    def get(self, key: str) -> Tuple[Any, bool]:
        """
        Get cached value by key.

        Args:
            key: The cache key

        Returns:
            Tuple of (value, is_valid). is_valid is False if key not found
            or entry expired.
        """
        with self._local_lock:
            cache = self._read_cache()
            if key in cache:
                entry = cache[key]
                try:
                    timestamp = datetime.fromisoformat(entry['timestamp'])
                    if datetime.now() - timestamp < timedelta(seconds=self._duration):
                        value = self._deserializer(entry['data']) if entry['data'] is not None else None
                        return (value, True)
                except (KeyError, ValueError) as e:
                    logger.debug(f"Invalid cache entry for {key}: {e}")
            return (None, False)

    def set(self, key: str, value: Any) -> None:
        """
        Set a cache entry.

        Args:
            key: The cache key
            value: The value to cache (will be serialized)
        """
        with self._local_lock:
            cache = self._read_cache()
            try:
                serialized = self._serializer(value) if value is not None else None
                cache[key] = {
                    'data': serialized,
                    'timestamp': datetime.now().isoformat()
                }
                self._write_cache(cache)
            except Exception as e:
                logger.warning(f"Failed to serialize cache value for {key}: {e}")

    def delete(self, key: str) -> bool:
        """
        Delete a cache entry.

        Args:
            key: The cache key to delete

        Returns:
            True if key existed and was deleted, False otherwise
        """
        with self._local_lock:
            cache = self._read_cache()
            if key in cache:
                del cache[key]
                self._write_cache(cache)
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries by deleting the cache file."""
        with self._local_lock:
            try:
                if self._cache_file.exists():
                    self._cache_file.unlink()
            except IOError as e:
                logger.warning(f"Failed to clear cache: {e}")

    def prune_expired(self) -> int:
        """
        Remove expired entries from the cache.

        Returns:
            Count of entries removed
        """
        with self._local_lock:
            cache = self._read_cache()
            now = datetime.now()
            expired = []

            for key, entry in cache.items():
                try:
                    timestamp = datetime.fromisoformat(entry['timestamp'])
                    if now - timestamp >= timedelta(seconds=self._duration):
                        expired.append(key)
                except (KeyError, ValueError):
                    expired.append(key)

            for key in expired:
                del cache[key]

            if expired:
                self._write_cache(cache)

            return len(expired)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        cache = self._read_cache()
        now = datetime.now()
        valid = 0
        expired = 0

        for entry in cache.values():
            try:
                timestamp = datetime.fromisoformat(entry['timestamp'])
                if now - datetime.fromisoformat(entry['timestamp']) < timedelta(seconds=self._duration):
                    valid += 1
                else:
                    expired += 1
            except (KeyError, ValueError):
                expired += 1

        return {
            'total_entries': len(cache),
            'valid_entries': valid,
            'expired_entries': expired,
            'cache_duration_seconds': self._duration,
            'cache_file': str(self._cache_file)
        }

    def keys(self) -> list:
        """Get all cache keys (including expired)."""
        cache = self._read_cache()
        return list(cache.keys())

    def __contains__(self, key: str) -> bool:
        """Check if key exists and is valid."""
        _, is_valid = self.get(key)
        return is_valid
