"""Read-through cache for provider lookups.

Rate limits are the scarce resource, so the same hash or address must never be
looked up twice. Failed lookups are deliberately not cached: a timeout is
transient, and remembering it would make the report claim "unknown" for the rest
of the TTL when a retry would have produced a real answer.
"""

from typing import Any, Callable
import time

from .base import UNAVAILABLE, ProviderResult


class EnrichmentCache:
    def __init__(
        self,
        ttl_seconds: float = 24 * 60 * 60,
        now: Callable[[], float] = time.time,
    ):
        self._ttl = ttl_seconds
        self._now = now
        self._entries: dict[tuple[str, str], tuple[float, ProviderResult]] = {}

    def get_or_fetch(
        self,
        provider: str,
        indicator: str,
        fetch: Callable[[], ProviderResult],
    ) -> ProviderResult:
        key = (provider, indicator)
        entry = self._entries.get(key)
        if entry is not None and self._now() - entry[0] <= self._ttl:
            return entry[1]

        result = fetch()
        if result.status != UNAVAILABLE:
            self._entries[key] = (self._now(), result)
        return result

    def stats(self) -> dict[str, Any]:
        return {"entries": len(self._entries)}
