import zipfile
from pathlib import Path

import pytest

from app.analysis.enrichment import Enricher
from app.analysis.hashing import hash_file
from app.analysis.pipeline import analyze_sample
from app.analysis.reputation.base import ProviderResult
from app.analysis.summary import IndicatorFinding
from app.analysis.yara_scan import YaraScanner

FIXTURE = Path(__file__).parent / "fixtures" / "benign_pe32.exe"


@pytest.fixture
def scanner(tmp_path):
    """An empty ruleset — YARA behaviour is covered in test_yara_scan.py."""
    rules = tmp_path / "rules"
    rules.mkdir()
    return YaraScanner(rules)


@pytest.fixture
def offline_enricher():
    return Enricher(offline=True)


class StubEnricher:
    """Returns a fixed ThreatFox hit so verdict propagation can be checked."""

    def __init__(self):
        self.hash_lookups: list[str] = []

    def enrich_hash(self, sha256):
        self.hash_lookups.append(sha256)
        return {"virustotal": ProviderResult("virustotal", "not_found")}

    def enrich_indicators(self, indicators):
        return [
            IndicatorFinding(
                indicator.type,
                indicator.value,
                threatfox=ProviderResult(
                    "threatfox", "ok", data={"malware": "AgentTesla", "threat_type": "botnet_cc"}
                ),
            )
            for indicator in indicators
        ]


def analyze(path, name, scanner, enricher, tmp_path):
    return analyze_sample(
        path, name, scanner=scanner, enricher=enricher, workdir=tmp_path / "work"
    )


class TestSingleFile:
    def test_records_the_hashes_of_the_uploaded_file(
        self, scanner, offline_enricher, tmp_path
    ):
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        assert result.sha256 == hash_file(FIXTURE)["sha256"]

    def test_identifies_the_file_type(self, scanner, offline_enricher, tmp_path):
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        assert "PE32" in result.detected_type

    def test_parses_the_pe_and_attaches_it_to_the_leaf(
        self, scanner, offline_enricher, tmp_path
    ):
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        (leaf,) = result.files
        assert leaf.pe is not None
        assert leaf.pe.machine == "x86"

    def test_a_benign_file_produces_an_unknown_verdict(
        self, scanner, offline_enricher, tmp_path
    ):
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        assert result.summary.level == "unknown"

    def test_version_numbers_are_not_reported_as_network_addresses(
        self, scanner, offline_enricher, tmp_path
    ):
        # The fixture's version resource reads "1.1.0.14", which a naive regex
        # reports as an exfiltration destination.
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        assert [i.value for i in result.indicators if i.type == "ipv4"] == []

    def test_a_non_pe_file_still_produces_a_report(
        self, scanner, offline_enricher, tmp_path
    ):
        text = tmp_path / "notes.txt"
        text.write_bytes(b"just some text with http://evil.example.com/gate.php inside")

        result = analyze(text, "notes.txt", scanner, offline_enricher, tmp_path)

        assert result.files[0].pe is None
        assert "evil.example.com" in [i.value for i in result.indicators]


class TestArchives:
    def test_reports_each_file_inside_an_archive(
        self, scanner, offline_enricher, tmp_path
    ):
        archive = tmp_path / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.write(FIXTURE, "payload.exe")
            handle.writestr("readme.txt", b"nothing to see")

        result = analyze(archive, "bundle.zip", scanner, offline_enricher, tmp_path)

        assert sorted(f.relative_name for f in result.files) == [
            "payload.exe",
            "readme.txt",
        ]

    def test_surfaces_extraction_warnings_in_the_report(
        self, scanner, offline_enricher, tmp_path
    ):
        archive = tmp_path / "slip.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../escaped.txt", b"escaped")

        result = analyze(archive, "slip.zip", scanner, offline_enricher, tmp_path)

        assert any("traversal" in w.lower() for w in result.warnings)


class TestOfflineMode:
    def test_offline_mode_still_produces_a_complete_report(
        self, scanner, offline_enricher, tmp_path
    ):
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        assert result.sha256
        assert result.summary.narrative

    def test_offline_mode_marks_every_provider_as_skipped(
        self, scanner, offline_enricher, tmp_path
    ):
        result = analyze(FIXTURE, "benign_pe32.exe", scanner, offline_enricher, tmp_path)

        assert result.provider_statuses
        assert all(p.status == "skipped" for p in result.provider_statuses)


class TestEnrichmentFlowsIntoTheVerdict:
    def test_a_known_c2_destination_makes_the_sample_malicious(
        self, scanner, tmp_path
    ):
        text = tmp_path / "beacon.txt"
        text.write_bytes(b"phone home to http://panel.evil.tk/gate.php")

        result = analyze(text, "beacon.txt", scanner, StubEnricher(), tmp_path)

        assert result.summary.level == "malicious"
        assert "AgentTesla" in result.summary.narrative

    def test_the_sample_hash_is_the_one_sent_for_reputation_lookup(
        self, scanner, tmp_path
    ):
        enricher = StubEnricher()

        result = analyze(FIXTURE, "benign_pe32.exe", scanner, enricher, tmp_path)

        assert enricher.hash_lookups == [result.sha256]
