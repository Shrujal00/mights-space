"""Shared plumbing for threat-intelligence providers.

Every provider is isolated: a missing key, a timeout, a rate-limit response or a
malformed body produces a `ProviderResult` describing the problem rather than an
exception. One provider being down must never cost the investigator the rest of
the report.
"""

from dataclasses import dataclass, field
from typing import Any

import httpx

OK = "ok"
NOT_FOUND = "not_found"
UNAVAILABLE = "unavailable"
SKIPPED = "skipped"


@dataclass
class ProviderResult:
    provider: str
    status: str  # ok | not_found | unavailable | skipped
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


class ReputationClient:
    """Base class holding the HTTP call, rate limiting and result helpers."""

    name = "unknown"

    def __init__(
        self,
        timeout: float = 15.0,
        rate_limiter: Any | None = None,
        client: httpx.Client | None = None,
    ):
        self._timeout = timeout
        self._rate_limiter = rate_limiter
        self._client = client

    def _http(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._rate_limiter is not None:
            self._rate_limiter.acquire()
        if self._client is not None:
            return self._client.request(method, url, **kwargs)
        with httpx.Client(timeout=self._timeout) as client:
            return client.request(method, url, **kwargs)

    def ok(self, detail: str = "", **data: Any) -> ProviderResult:
        return ProviderResult(self.name, OK, detail=detail, data=data)

    def not_found(self, detail: str = "") -> ProviderResult:
        return ProviderResult(self.name, NOT_FOUND, detail=detail)

    def unavailable(self, detail: str) -> ProviderResult:
        return ProviderResult(self.name, UNAVAILABLE, detail=detail)

    def skipped(self, detail: str = "no API key configured") -> ProviderResult:
        return ProviderResult(self.name, SKIPPED, detail=detail)
