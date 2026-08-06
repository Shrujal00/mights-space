"""VirusTotal v3 hash reputation.

Only the SHA256 is ever sent. Uploading the file itself would publish potential
evidence to a multi-scanner where it can be downloaded by other subscribers,
which is unacceptable for material taken from a victim's or suspect's device.
A hash lookup discloses nothing about the file's contents.

Public tier: 4 requests/minute, 500/day.
"""

import httpx

from .base import ReputationClient

BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient(ReputationClient):
    name = "virustotal"

    def __init__(self, api_key: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.api_key = api_key

    def lookup_hash(self, sha256: str):
        if not self.api_key:
            return self.skipped()

        try:
            response = self._http(
                "GET",
                f"{BASE_URL}/files/{sha256}",
                headers={"x-apikey": self.api_key},
            )
        except httpx.HTTPError as exc:
            return self.unavailable(f"request failed: {exc}")

        if response.status_code == 404:
            return self.not_found("hash not known to VirusTotal")
        if response.status_code == 401:
            return self.unavailable("VirusTotal rejected the API key")
        if response.status_code == 429:
            return self.unavailable("VirusTotal rate limit exceeded")
        if response.status_code != 200:
            return self.unavailable(f"HTTP {response.status_code}")

        try:
            attributes = response.json()["data"]["attributes"]
        except (ValueError, KeyError, TypeError) as exc:
            return self.unavailable(f"unexpected response body: {exc}")

        stats = attributes.get("last_analysis_stats") or {}
        classification = attributes.get("popular_threat_classification") or {}
        return self.ok(
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            total_engines=sum(stats.values()) if stats else 0,
            threat_label=classification.get("suggested_threat_label"),
            meaningful_name=attributes.get("meaningful_name"),
        )
