import csv
import io
import json

from app.analysis.export.csv_export import iocs_to_csv
from app.analysis.export.stix_export import iocs_to_stix
from app.analysis.reputation.base import ProviderResult
from app.analysis.summary import IndicatorFinding
from app.analysis.export.model import ReportExport


def sample_report():
    return ReportExport(
        sha256="a" * 64,
        md5="b" * 32,
        sha1="c" * 40,
        filename="invoice.exe",
        verdict="malicious",
        yara_rules=["MAL_AgentTesla_Nov23"],
        indicators=[
            IndicatorFinding(
                "ipv4",
                "185.244.25.14",
                threatfox=ProviderResult(
                    "threatfox",
                    "ok",
                    data={"malware": "AgentTesla", "threat_type": "botnet_cc"},
                ),
                abuseipdb=ProviderResult(
                    "abuseipdb", "ok", data={"abuse_confidence": 100, "country": "RU"}
                ),
            ),
            IndicatorFinding("domain", "panel.evil.tk"),
            IndicatorFinding("url", "http://panel.evil.tk/gate.php"),
        ],
    )


def parse_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


class TestCsvExport:
    def test_writes_one_row_per_indicator(self):
        rows = parse_csv(iocs_to_csv(sample_report()))

        assert len(rows) == 3

    def test_records_indicator_type_and_value(self):
        rows = parse_csv(iocs_to_csv(sample_report()))

        assert rows[0]["indicator_type"] == "ipv4"
        assert rows[0]["indicator_value"] == "185.244.25.14"

    def test_carries_threat_intelligence_columns(self):
        rows = parse_csv(iocs_to_csv(sample_report()))

        assert rows[0]["threatfox_malware"] == "AgentTesla"
        assert rows[0]["abuseipdb_confidence"] == "100"

    def test_ties_every_row_back_to_the_sample_hash(self):
        rows = parse_csv(iocs_to_csv(sample_report()))

        assert all(row["sample_sha256"] == "a" * 64 for row in rows)

    def test_leaves_unenriched_columns_empty_rather_than_absent(self):
        rows = parse_csv(iocs_to_csv(sample_report()))

        assert rows[1]["threatfox_malware"] == ""

    def test_a_report_without_indicators_still_has_a_header(self):
        empty = ReportExport(sha256="a" * 64, filename="x.bin", verdict="unknown")

        text = iocs_to_csv(empty)

        assert "indicator_value" in text.splitlines()[0]


class TestStixExport:
    def test_produces_a_stix_bundle(self):
        bundle = json.loads(iocs_to_stix(sample_report()))

        assert bundle["type"] == "bundle"

    def test_includes_an_indicator_for_each_network_ioc(self):
        bundle = json.loads(iocs_to_stix(sample_report()))
        patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]

        assert "[ipv4-addr:value = '185.244.25.14']" in patterns
        assert "[domain-name:value = 'panel.evil.tk']" in patterns
        assert "[url:value = 'http://panel.evil.tk/gate.php']" in patterns

    def test_includes_the_sample_hash_as_an_indicator(self):
        bundle = json.loads(iocs_to_stix(sample_report()))
        patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]

        assert f"[file:hashes.'SHA-256' = '{'a' * 64}']" in patterns

    def test_every_indicator_declares_the_stix_pattern_type(self):
        bundle = json.loads(iocs_to_stix(sample_report()))

        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert all(o["pattern_type"] == "stix" for o in indicators)

    def test_names_the_malware_family_on_a_known_c2_indicator(self):
        bundle = json.loads(iocs_to_stix(sample_report()))

        c2 = next(
            o
            for o in bundle["objects"]
            if o["type"] == "indicator" and "185.244.25.14" in o["pattern"]
        )
        assert "AgentTesla" in json.dumps(c2)

    def test_a_report_without_indicators_still_produces_a_valid_bundle(self):
        empty = ReportExport(sha256="a" * 64, filename="x.bin", verdict="unknown")

        bundle = json.loads(iocs_to_stix(empty))

        assert bundle["type"] == "bundle"
