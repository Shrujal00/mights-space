"""Threat-intelligence enrichment across all configured providers.

Three concerns live here: which provider answers which kind of indicator, the
per-sample budget that keeps VirusTotal's four-requests-per-minute limit from
stalling a report, and the guarantee that one failing provider never costs the
investigator the rest of the analysis.

With `offline=True` nothing touches the network and every provider is reported
as skipped, which is how the tool runs against a sample too sensitive to take
near a networked machine.
"""

from dataclasses import dataclass, field

from ..config import Settings
from .ioc_extract import Indicator
from .reputation.abuseipdb import AbuseIPDBClient
from .reputation.base import ProviderResult
from .reputation.cache import EnrichmentCache
from .reputation.malwarebazaar import MalwareBazaarClient
from .reputation.ratelimit import RateLimiter
from .reputation.threatfox import ThreatFoxClient
from .reputation.urlscan import UrlscanClient
from .reputation.virustotal import VirusTotalClient
from .summary import IndicatorFinding


@dataclass
class _Clients:
    virustotal: VirusTotalClient
    malwarebazaar: MalwareBazaarClient
    threatfox: ThreatFoxClient
    abuseipdb: AbuseIPDBClient
    urlscan: UrlscanClient


class Enricher:
    def __init__(
        self,
        settings: Settings | None = None,
        offline: bool = False,
        cache: EnrichmentCache | None = None,
        clients: _Clients | None = None,
    ):
        self.settings = settings or Settings()
        self.offline = offline or self.settings.offline_mode
        self.cache = cache or EnrichmentCache()
        self.clients = clients or self._build_clients()

    def _build_clients(self) -> _Clients:
        virustotal_limiter = RateLimiter(
            max_calls=self.settings.virustotal_calls_per_minute, per_seconds=60.0
        )
        return _Clients(
            virustotal=VirusTotalClient(
                api_key=self.settings.vt_api_key, rate_limiter=virustotal_limiter
            ),
            malwarebazaar=MalwareBazaarClient(auth_key=self.settings.abusech_auth_key),
            threatfox=ThreatFoxClient(auth_key=self.settings.abusech_auth_key),
            abuseipdb=AbuseIPDBClient(api_key=self.settings.abuseipdb_api_key),
            urlscan=UrlscanClient(api_key=self.settings.urlscan_api_key),
        )

    def enrich_hash(self, sha256: str) -> dict[str, ProviderResult]:
        """Reputation for the sample itself. Only the hash is ever transmitted."""
        if self.offline:
            return {
                "virustotal": self._offline("virustotal"),
                "malwarebazaar": self._offline("malwarebazaar"),
            }
        return {
            "virustotal": self.cache.get_or_fetch(
                "virustotal", sha256, lambda: self.clients.virustotal.lookup_hash(sha256)
            ),
            "malwarebazaar": self.cache.get_or_fetch(
                "malwarebazaar",
                sha256,
                lambda: self.clients.malwarebazaar.lookup_hash(sha256),
            ),
        }

    def enrich_indicators(self, indicators: list[Indicator]) -> list[IndicatorFinding]:
        budget = self.settings.max_indicator_lookups_per_sample
        findings: list[IndicatorFinding] = []

        for position, indicator in enumerate(indicators):
            finding = IndicatorFinding(indicator.type, indicator.value)
            if not self.offline and position < budget:
                self._enrich_one(finding, indicator)
            findings.append(finding)

        return findings

    def _enrich_one(self, finding: IndicatorFinding, indicator: Indicator) -> None:
        value = indicator.value
        finding.threatfox = self.cache.get_or_fetch(
            "threatfox", value, lambda: self.clients.threatfox.lookup_ioc(value)
        )
        if indicator.type == "ipv4":
            finding.abuseipdb = self.cache.get_or_fetch(
                "abuseipdb", value, lambda: self.clients.abuseipdb.lookup_ip(value)
            )
        elif indicator.type == "domain":
            finding.urlscan = self.cache.get_or_fetch(
                "urlscan", value, lambda: self.clients.urlscan.lookup_domain(value)
            )

    @staticmethod
    def _offline(provider: str) -> ProviderResult:
        return ProviderResult(
            provider, "skipped", detail="offline mode: no network lookups performed"
        )
