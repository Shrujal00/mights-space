import httpx
import pytest
import respx

from app.analysis.reputation.abuseipdb import AbuseIPDBClient
from app.analysis.reputation.malwarebazaar import MalwareBazaarClient
from app.analysis.reputation.threatfox import ThreatFoxClient
from app.analysis.reputation.urlscan import UrlscanClient
from app.analysis.reputation.virustotal import VirusTotalClient

SHA256 = "a" * 64


class TestVirusTotal:
    URL = f"https://www.virustotal.com/api/v3/files/{SHA256}"

    @respx.mock
    def test_reports_detection_counts(self):
        respx.get(self.URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 45,
                                "suspicious": 2,
                                "undetected": 20,
                                "harmless": 0,
                            },
                            "meaningful_name": "invoice.exe",
                            "popular_threat_classification": {
                                "suggested_threat_label": "trojan.agenttesla/stealer"
                            },
                        }
                    }
                },
            )
        )

        result = VirusTotalClient(api_key="key").lookup_hash(SHA256)

        assert result.status == "ok"
        assert result.data["malicious"] == 45
        assert result.data["threat_label"] == "trojan.agenttesla/stealer"

    @respx.mock
    def test_sends_only_the_hash_never_the_file(self):
        route = respx.get(self.URL).mock(return_value=httpx.Response(404))

        VirusTotalClient(api_key="key").lookup_hash(SHA256)

        request = route.calls.last.request
        assert request.method == "GET"
        assert not request.content

    @respx.mock
    def test_unknown_hash_is_reported_as_not_found(self):
        respx.get(self.URL).mock(return_value=httpx.Response(404))

        assert VirusTotalClient(api_key="key").lookup_hash(SHA256).status == "not_found"

    @respx.mock
    def test_rate_limit_response_is_unavailable_not_a_crash(self):
        respx.get(self.URL).mock(return_value=httpx.Response(429))

        result = VirusTotalClient(api_key="key").lookup_hash(SHA256)

        assert result.status == "unavailable"

    @respx.mock
    def test_a_timeout_does_not_propagate(self):
        respx.get(self.URL).mock(side_effect=httpx.ConnectTimeout("timed out"))

        assert VirusTotalClient(api_key="key").lookup_hash(SHA256).status == "unavailable"

    @respx.mock
    def test_without_a_key_the_provider_is_skipped_and_no_request_is_made(self):
        route = respx.get(self.URL).mock(return_value=httpx.Response(200, json={}))

        result = VirusTotalClient(api_key=None).lookup_hash(SHA256)

        assert result.status == "skipped"
        assert not route.called


class TestMalwareBazaar:
    URL = "https://mb-api.abuse.ch/api/v1/"

    @respx.mock
    def test_reports_the_malware_family(self):
        respx.post(self.URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [
                        {
                            "signature": "AgentTesla",
                            "file_type": "exe",
                            "tags": ["exe", "AgentTesla"],
                            "first_seen": "2024-01-01 10:00:00",
                        }
                    ],
                },
            )
        )

        result = MalwareBazaarClient(auth_key="key").lookup_hash(SHA256)

        assert result.status == "ok"
        assert result.data["signature"] == "AgentTesla"

    @respx.mock
    def test_sends_the_required_auth_key_header(self):
        # abuse.ch made authentication mandatory; without this header every
        # lookup silently fails.
        route = respx.post(self.URL).mock(
            return_value=httpx.Response(200, json={"query_status": "hash_not_found"})
        )

        MalwareBazaarClient(auth_key="secret-key").lookup_hash(SHA256)

        assert route.calls.last.request.headers["Auth-Key"] == "secret-key"

    @respx.mock
    def test_unknown_hash_is_reported_as_not_found(self):
        respx.post(self.URL).mock(
            return_value=httpx.Response(200, json={"query_status": "hash_not_found"})
        )

        result = MalwareBazaarClient(auth_key="key").lookup_hash(SHA256)

        assert result.status == "not_found"

    @respx.mock
    def test_server_error_is_unavailable(self):
        respx.post(self.URL).mock(return_value=httpx.Response(500))

        assert MalwareBazaarClient(auth_key="k").lookup_hash(SHA256).status == "unavailable"

    @respx.mock
    def test_without_a_key_the_provider_is_skipped(self):
        route = respx.post(self.URL)

        assert MalwareBazaarClient(auth_key=None).lookup_hash(SHA256).status == "skipped"
        assert not route.called


class TestThreatFox:
    URL = "https://threatfox-api.abuse.ch/api/v1/"

    @respx.mock
    def test_identifies_a_known_command_and_control_address(self):
        respx.post(self.URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [
                        {
                            "ioc": "185.244.25.14:443",
                            "threat_type": "botnet_cc",
                            "malware_printable": "AgentTesla",
                            "confidence_level": 75,
                        }
                    ],
                },
            )
        )

        result = ThreatFoxClient(auth_key="key").lookup_ioc("185.244.25.14")

        assert result.status == "ok"
        assert result.data["malware"] == "AgentTesla"
        assert result.data["threat_type"] == "botnet_cc"

    @respx.mock
    def test_unknown_indicator_is_reported_as_not_found(self):
        respx.post(self.URL).mock(
            return_value=httpx.Response(200, json={"query_status": "no_result"})
        )

        result = ThreatFoxClient(auth_key="key").lookup_ioc("185.244.25.14")

        assert result.status == "not_found"

    @respx.mock
    def test_without_a_key_the_provider_is_skipped(self):
        route = respx.post(self.URL)

        assert ThreatFoxClient(auth_key=None).lookup_ioc("1.2.3.4").status == "skipped"
        assert not route.called


class TestAbuseIPDB:
    URL = "https://api.abuseipdb.com/api/v2/check"

    @respx.mock
    def test_reports_the_abuse_confidence_score(self):
        respx.get(self.URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "ipAddress": "185.244.25.14",
                        "abuseConfidenceScore": 100,
                        "totalReports": 56,
                        "countryCode": "RU",
                        "isp": "Example Hosting",
                    }
                },
            )
        )

        result = AbuseIPDBClient(api_key="key").lookup_ip("185.244.25.14")

        assert result.status == "ok"
        assert result.data["abuse_confidence"] == 100
        assert result.data["country"] == "RU"

    @respx.mock
    def test_server_error_is_unavailable(self):
        respx.get(self.URL).mock(return_value=httpx.Response(500))

        assert AbuseIPDBClient(api_key="k").lookup_ip("1.2.3.4").status == "unavailable"

    @respx.mock
    def test_without_a_key_the_provider_is_skipped(self):
        route = respx.get(self.URL)

        assert AbuseIPDBClient(api_key=None).lookup_ip("1.2.3.4").status == "skipped"
        assert not route.called


class TestUrlscan:
    URL = "https://urlscan.io/api/v1/search/"

    @respx.mock
    def test_reports_prior_scans_of_a_domain(self):
        respx.get(self.URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "total": 1,
                    "results": [
                        {
                            "page": {"url": "http://evil.example.com/"},
                            "task": {"time": "2024-01-01T00:00:00.000Z"},
                        }
                    ],
                },
            )
        )

        result = UrlscanClient(api_key="key").lookup_domain("evil.example.com")

        assert result.status == "ok"
        assert result.data["result_count"] == 1

    @respx.mock
    def test_searches_and_never_submits(self):
        # Submitting makes a URL public by default, which could expose case
        # material or tip off live infrastructure that it is being investigated.
        route = respx.get(self.URL).mock(
            return_value=httpx.Response(200, json={"total": 0, "results": []})
        )

        UrlscanClient(api_key="key").lookup_domain("evil.example.com")

        request = route.calls.last.request
        assert request.method == "GET"
        assert "/search/" in str(request.url)

    @respx.mock
    def test_no_prior_scans_is_reported_as_not_found(self):
        respx.get(self.URL).mock(
            return_value=httpx.Response(200, json={"total": 0, "results": []})
        )

        result = UrlscanClient(api_key="key").lookup_domain("evil.example.com")

        assert result.status == "not_found"

    @respx.mock
    def test_without_a_key_the_provider_is_skipped(self):
        route = respx.get(self.URL)

        assert UrlscanClient(api_key=None).lookup_domain("x.com").status == "skipped"
        assert not route.called
