"""urlscan.io lookups — search only, never submit.

Submitting a URL to urlscan makes the resulting scan public by default. For a
police tool that would expose material from an active case, and would signal to
whoever operates the infrastructure that it is being investigated. This client
therefore only ever queries the search endpoint for scans that already exist.
"""

import httpx

from .base import ReputationClient

SEARCH_URL = "https://urlscan.io/api/v1/search/"


class UrlscanClient(ReputationClient):
    name = "urlscan"

    def __init__(self, api_key: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key

    def lookup_domain(self, domain: str):
        if not self.api_key:
            return self.skipped()

        try:
            response = self._http(
                "GET",
                SEARCH_URL,
                headers={"API-Key": self.api_key},
                params={"q": f"domain:{domain}"},
            )
        except httpx.HTTPError as exc:
            return self.unavailable(f"request failed: {exc}")

        if response.status_code == 429:
            return self.unavailable("urlscan rate limit exceeded")
        if response.status_code != 200:
            return self.unavailable(f"HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            return self.unavailable(f"unexpected response body: {exc}")

        results = payload.get("results") or []
        if not results:
            return self.not_found("no existing urlscan reports for this domain")

        latest = results[0]
        return self.ok(
            result_count=payload.get("total", len(results)),
            latest_url=(latest.get("page") or {}).get("url"),
            latest_scan_time=(latest.get("task") or {}).get("time"),
        )
