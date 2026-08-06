from datetime import datetime, timezone

from app.analysis.attack_map import Technique
from app.analysis.behavior import DetonationResult
from app.analysis.exfiltration import ExfiltrationFinding
from app.analysis.pe_analysis import PackingAssessment
from app.analysis.reputation.base import ProviderResult
from app.analysis.summary import IndicatorFinding, SampleFindings, summarize


def vt(malicious, total=70):
    return ProviderResult(
        "virustotal",
        "ok",
        data={
            "malicious": malicious,
            "total_engines": total,
            "threat_label": "trojan.agenttesla/stealer",
        },
    )


def threatfox_hit(malware="AgentTesla"):
    return ProviderResult(
        "threatfox",
        "ok",
        data={"malware": malware, "threat_type": "botnet_cc", "confidence": 100},
    )


class TestVerdict:
    def test_many_antivirus_detections_are_malicious(self):
        assert summarize(SampleFindings(virustotal=vt(45))).level == "malicious"

    def test_a_malwarebazaar_listing_is_malicious(self):
        findings = SampleFindings(
            malwarebazaar=ProviderResult(
                "malwarebazaar", "ok", data={"signature": "AgentTesla"}
            )
        )

        assert summarize(findings).level == "malicious"

    def test_a_destination_known_as_command_and_control_is_malicious(self):
        findings = SampleFindings(
            indicators=[
                IndicatorFinding("ipv4", "185.244.25.14", threatfox=threatfox_hit())
            ]
        )

        assert summarize(findings).level == "malicious"

    def test_a_handful_of_detections_is_suspicious(self):
        assert summarize(SampleFindings(virustotal=vt(3))).level == "suspicious"

    def test_a_yara_match_alone_is_suspicious_not_malicious(self):
        # Community rules generate false positives; a signature hit on its own
        # warrants a look, not an accusation.
        findings = SampleFindings(yara_rules=["SUSP_Obfuscated_Script"])

        assert summarize(findings).level == "suspicious"

    def test_packing_alone_is_suspicious(self):
        findings = SampleFindings(
            packing=PackingAssessment(likely_packed=True, reasons=["UPX0"])
        )

        assert summarize(findings).level == "suspicious"

    def test_nothing_found_is_unknown(self):
        assert summarize(SampleFindings()).level == "unknown"

    def test_zero_detections_from_virustotal_is_still_only_unknown(self):
        assert summarize(SampleFindings(virustotal=vt(0))).level == "unknown"


class TestNarrative:
    def test_a_clean_result_never_claims_the_file_is_safe(self):
        # An officer may act on this wording. Absence of evidence is not
        # evidence of absence, and the report must not imply otherwise.
        narrative = summarize(SampleFindings()).narrative.lower()

        assert "safe" not in narrative
        assert "clean" not in narrative

    def test_states_that_the_file_was_never_run(self):
        findings = SampleFindings(
            techniques=[
                Technique("T1113", "Screen Capture", "Can take pictures of the screen.", ("BitBlt",))
            ]
        )

        assert "was not run" in summarize(findings).narrative.lower()

    def test_describes_capabilities_in_plain_language(self):
        findings = SampleFindings(
            techniques=[
                Technique(
                    "T1056.001",
                    "Input Capture: Keylogging",
                    "Can record everything typed on the keyboard.",
                    ("SetWindowsHookExA",),
                )
            ]
        )

        summary = summarize(findings)

        assert "Can record everything typed on the keyboard." in summary.capabilities
        assert "keyboard" in summary.narrative.lower()

    def test_names_the_command_and_control_server_and_the_malware_family(self):
        findings = SampleFindings(
            indicators=[
                IndicatorFinding("ipv4", "185.244.25.14", threatfox=threatfox_hit())
            ]
        )

        summary = summarize(findings)

        assert "185.244.25.14" in summary.narrative
        assert "AgentTesla" in summary.narrative

    def test_cites_the_antivirus_detection_count_as_a_reason(self):
        summary = summarize(SampleFindings(virustotal=vt(45, total=70)))

        assert any("45" in reason and "70" in reason for reason in summary.reasons)

    def test_lists_contact_destinations_separately_from_capabilities(self):
        findings = SampleFindings(
            indicators=[
                IndicatorFinding("domain", "panel.evil.tk"),
                IndicatorFinding("ipv4", "185.244.25.14"),
            ]
        )

        summary = summarize(findings)

        assert sorted(summary.destinations) == ["185.244.25.14", "panel.evil.tk"]

    def test_headline_reflects_the_verdict(self):
        assert "malicious" in summarize(SampleFindings(virustotal=vt(45))).headline.lower()

    def test_mentions_an_abusive_address_even_without_a_threatfox_match(self):
        findings = SampleFindings(
            indicators=[
                IndicatorFinding(
                    "ipv4",
                    "185.244.25.14",
                    abuseipdb=ProviderResult(
                        "abuseipdb",
                        "ok",
                        data={"abuse_confidence": 100, "country": "RU"},
                    ),
                )
            ]
        )

        assert "185.244.25.14" in summarize(findings).narrative


def exfiltration(where="185.244.25.14:443", what="247 messages from SMS inbox"):
    return ExfiltrationFinding(
        what=what,
        where=where,
        when=datetime(2026, 8, 6, 14, 3, 22, tzinfo=timezone.utc),
        gap_ms=3000,
        bytes_sent=34816,
        confidence="strong",
    )


def detonation(status="complete", platform="android", engine="frida"):
    return DetonationResult(
        platform=platform,
        engine=engine,
        status=status,
        started_at=datetime(2026, 8, 6, 14, 3, 20, tzinfo=timezone.utc),
        finished_at=datetime(2026, 8, 6, 14, 5, 20, tzinfo=timezone.utc),
    )


class TestObservedExfiltration:
    def test_data_sent_to_a_known_command_and_control_server_is_malicious(self):
        findings = SampleFindings(
            exfiltration=[exfiltration()],
            indicators=[IndicatorFinding("ip", "185.244.25.14", threatfox=threatfox_hit())],
            detonation=detonation(),
        )

        assert summarize(findings).level == "malicious"

    def test_the_reason_names_what_was_taken_and_where_it_went(self):
        findings = SampleFindings(
            exfiltration=[exfiltration()],
            indicators=[IndicatorFinding("ip", "185.244.25.14", threatfox=threatfox_hit())],
            detonation=detonation(),
        )

        reasons = " ".join(summarize(findings).reasons)

        assert "247 messages from SMS inbox" in reasons
        assert "185.244.25.14" in reasons

    def test_the_port_does_not_stop_the_destination_matching_a_known_server(self):
        """Observed destinations carry a port; threat intelligence is keyed on
        the address alone. A mismatch here would silently downgrade the verdict
        on the strongest evidence the system can produce."""
        findings = SampleFindings(
            exfiltration=[exfiltration(where="185.244.25.14:443")],
            indicators=[IndicatorFinding("ip", "185.244.25.14", threatfox=threatfox_hit())],
            detonation=detonation(),
        )

        assert summarize(findings).level == "malicious"

    def test_data_sent_to_an_unremarkable_address_is_suspicious_not_malicious(self):
        findings = SampleFindings(
            exfiltration=[exfiltration(where="api.example.com:443")],
            detonation=detonation(),
        )

        assert summarize(findings).level == "suspicious"

    def test_an_observed_transfer_is_described_as_observed_not_as_a_capability(self):
        findings = SampleFindings(
            exfiltration=[exfiltration(where="api.example.com:443")],
            detonation=detonation(),
        )

        reasons = " ".join(summarize(findings).reasons).lower()

        assert "observed" in reasons or "was seen" in reasons


class TestWhetherTheFileWasRun:
    def test_a_static_only_report_still_says_the_file_was_never_run(self):
        assert "was not run" in summarize(SampleFindings()).narrative.lower()

    def test_a_failed_detonation_still_says_the_file_was_never_run(self):
        """Nothing was observed, so nothing may be claimed as observed."""
        findings = SampleFindings(detonation=detonation(status="failed"))

        assert "was not run" in summarize(findings).narrative.lower()

    def test_a_report_from_a_detonated_sample_does_not_claim_it_was_never_run(self):
        findings = SampleFindings(detonation=detonation())

        assert "was not run" not in summarize(findings).narrative.lower()

    def test_a_detonated_sample_says_it_was_run_in_a_contained_sandbox(self):
        findings = SampleFindings(detonation=detonation())

        assert "sandbox" in summarize(findings).narrative.lower()

    def test_a_detonated_sample_says_when_it_was_run(self):
        findings = SampleFindings(detonation=detonation())

        assert "2026" in summarize(findings).narrative

    def test_an_emulated_windows_sample_says_its_code_never_ran_on_a_real_computer(self):
        findings = SampleFindings(
            detonation=detonation(platform="windows", engine="speakeasy")
        )

        assert "never ran on a real computer" in summarize(findings).narrative.lower()
