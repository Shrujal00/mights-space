"""ThreatFox (abuse.ch) command-and-control indicator lookup.

This is the provider that answers the question the whole tool exists to answer:
is this address or domain a known malware command-and-control server, and for
which family. Uses the same free abuse.ch `Auth-Key` as MalwareBazaar.
"""

import httpx

from .base import ReputationClient

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxClient(ReputationClient):
    name = "threatfox"

    def __init__(self, auth_key: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.auth_key = auth_key

    def lookup_ioc(self, indicator: str):
        if not self.auth_key:
            return self.skipped()

        try:
            response = self._http(
                "POST",
                API_URL,
                headers={"Auth-Key": self.auth_key},
                json={"query": "search_ioc", "search_term": indicator},
            )
        except httpx.HTTPError as exc:
            return self.unavailable(f"request failed: {exc}")

        if response.status_code != 200:
            return self.unavailable(f"HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            return self.unavailable(f"unexpected response body: {exc}")

        status = payload.get("query_status")
        if status in ("no_result", "illegal_search_term"):
            return self.not_found("indicator not present in ThreatFox")
        if status != "ok":
            return self.unavailable(f"query_status={status}")

        entries = payload.get("data") or [{}]
        entry = entries[0]
        return self.ok(
            malware=entry.get("malware_printable"),
            threat_type=entry.get("threat_type"),
            confidence=entry.get("confidence_level"),
            ioc=entry.get("ioc"),
            first_seen=entry.get("first_seen"),
        )
