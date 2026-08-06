"""AbuseIPDB reputation for extracted IPv4 addresses.

Free tier allows 1,000 checks per day, so this is only ever called for
addresses that survived the IOC noise filters.
"""

import httpx

from .base import ReputationClient

API_URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90


class AbuseIPDBClient(ReputationClient):
    name = "abuseipdb"

    def __init__(self, api_key: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key

    def lookup_ip(self, address: str):
        if not self.api_key:
            return self.skipped()

        try:
            response = self._http(
                "GET",
                API_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": address, "maxAgeInDays": MAX_AGE_DAYS},
            )
        except httpx.HTTPError as exc:
            return self.unavailable(f"request failed: {exc}")

        if response.status_code == 401:
            return self.unavailable("AbuseIPDB rejected the API key")
        if response.status_code == 429:
            return self.unavailable("AbuseIPDB daily quota exceeded")
        if response.status_code != 200:
            return self.unavailable(f"HTTP {response.status_code}")

        try:
            data = response.json()["data"]
        except (ValueError, KeyError, TypeError) as exc:
            return self.unavailable(f"unexpected response body: {exc}")

        return self.ok(
            abuse_confidence=data.get("abuseConfidenceScore", 0),
            total_reports=data.get("totalReports", 0),
            country=data.get("countryCode"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            last_reported=data.get("lastReportedAt"),
        )
