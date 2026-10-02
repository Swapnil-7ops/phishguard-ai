"""
services/threat_intelligence/cache.py - In-Memory Thread-Safe TTL Cache

WHAT: Lightweight thread-safe TTL cache for threat intelligence lookups.
WHY:  Avoids redundant network round-trips and respects third-party provider
      rate limits for repeated URL analyses.
HOW:  In-memory dict mapping normalized URLs to (ThreatIntelResult, expire_at) tuples
      guarded by a threading.Lock.
"""
import time
import threading
from typing import Optional, Dict, Tuple
from services.threat_intelligence.base import ThreatIntelResult


class SimpleThreatIntelCache:
    """Thread-safe in-memory cache with time-to-live (TTL) expiration."""

    def __init__(self, default_ttl_sec: int = 3600, max_entries: int = 2000):
        self._default_ttl = default_ttl_sec
        self._max_entries = max_entries
        self._store: Dict[str, Tuple[ThreatIntelResult, float]] = {}
        self._lock = threading.Lock()

    def get(self, url: str) -> Optional[ThreatIntelResult]:
        """Retrieve cached result if present and unexpired."""
        with self._lock:
            entry = self._store.get(url)
            if not entry:
                return None
            result, expire_at = entry
            if time.time() > expire_at:
                del self._store[url]
                return None
            return result

    def set(self, url: str, result: ThreatIntelResult, ttl_sec: Optional[int] = None) -> None:
        """Store lookup result with expiration timestamp."""
        ttl = ttl_sec if ttl_sec is not None else self._default_ttl
        expire_at = time.time() + ttl
        with self._lock:
            # If cache exceeds max entries, clear expired or prune oldest
            if len(self._store) >= self._max_entries:
                self._prune_expired()
                if len(self._store) >= self._max_entries:
                    # Drop oldest entry
                    oldest_key = next(iter(self._store))
                    del self._store[oldest_key]
            self._store[url] = (result, expire_at)

    def _prune_expired(self) -> None:
        """Internal helper to remove expired entries."""
        now = time.time()
        expired_keys = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired_keys:
            del self._store[k]

    def clear(self) -> None:
        """Clear all cached entries (useful for testing)."""
        with self._lock:
            self._store.clear()
