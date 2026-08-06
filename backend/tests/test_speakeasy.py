"""Windows emulation via Speakeasy.

The mapping from an emulator report to behaviour events is a pure function, so
almost everything here runs against hand-written report dictionaries and needs
no emulator. Two tests at the end drive the real thing against the benign
fixture.
"""

from datetime import datetime, timezone
from pathlib import Path

from app.analysis.behavior import DATA_ACCESS, FILE, NETWORK, PROCESS, REGISTRY
from app.sandbox.windows_speakeasy import detonate_pe, map_report

FIXTURE = Path(__file__).parent / "fixtures" / "benign_pe32.exe"
START = datetime(2026, 8, 6, 14, 3, 22, tzinfo=timezone.utc)


def report_with(apis=(), file_access=(), network=None):
    return {
        "entry_points": [
            {
                "ep_type": "module_entry",
                "apis": [{"api_name": name, "args": [], "ret_val": None} for name in apis],
                "file_access": list(file_access),
                "network_events": network,
                "error": None,
            }
        ]
    }


class TestApiMapping:
    def test_runtime_bookkeeping_calls_are_not_reported_as_behaviour(self):
        """A trace is mostly C-runtime noise. Reporting 60 TlsGetValue calls as
        observed behaviour would bury the two lines that matter."""
        events = map_report(
            report_with(apis=["KERNEL32.GetLastError", "KERNEL32.TlsGetValue"]), START
        )

        assert events == []

    def test_a_process_injection_call_is_reported_as_process_behaviour(self):
        events = map_report(report_with(apis=["KERNEL32.CreateRemoteThread"]), START)

        assert len(events) == 1
        assert events[0].category == PROCESS
        assert events[0].target == "KERNEL32.CreateRemoteThread"

    def test_an_event_explains_in_plain_language_what_the_call_does(self):
        events = map_report(report_with(apis=["KERNEL32.CreateRemoteThread"]), START)

        assert "hide its own code inside another running program" in events[0].detail

    def test_the_ansi_suffix_windows_appends_does_not_prevent_a_match(self):
        events = map_report(report_with(apis=["urlmon.URLDownloadToFileA"]), START)

        assert len(events) == 1
        assert events[0].category == NETWORK

    def test_a_registry_write_is_reported_as_registry_behaviour(self):
        events = map_report(report_with(apis=["ADVAPI32.RegSetValueExW"]), START)

        assert events[0].category == REGISTRY

    def test_reading_the_keyboard_is_reported_as_data_access(self):
        events = map_report(report_with(apis=["USER32.GetAsyncKeyState"]), START)

        assert events[0].category == DATA_ACCESS

    def test_encryption_calls_are_reported_as_crypto_behaviour(self):
        events = map_report(report_with(apis=["ADVAPI32.CryptEncrypt"]), START)

        assert events[0].category == "crypto"

    def test_a_repeated_call_is_reported_once_with_a_count(self):
        """Ten identical calls are one behaviour observed ten times, not ten
        separate findings competing for the reader's attention."""
        events = map_report(
            report_with(apis=["KERNEL32.CreateRemoteThread"] * 3), START
        )

        assert len(events) == 1
        assert "3 times" in events[0].detail

    def test_every_event_records_which_engine_saw_it(self):
        events = map_report(report_with(apis=["KERNEL32.CreateRemoteThread"]), START)

        assert events[0].source == "speakeasy"


class TestFileAndNetworkMapping:
    def test_a_file_the_sample_wrote_is_reported_with_its_path(self):
        events = map_report(
            report_with(
                file_access=[{"event": "write", "path": "C:\\Temp\\run.exe", "size": 2048}]
            ),
            START,
        )

        assert events[0].category == FILE
        assert events[0].action == "write"
        assert events[0].target == "C:\\Temp\\run.exe"
        assert "2048" in events[0].detail

    def test_a_domain_lookup_is_reported_with_the_name_and_the_address(self):
        events = map_report(
            report_with(network={"dns": [{"query": "evil.example", "response": "1.2.3.4"}]}),
            START,
        )

        assert events[0].category == NETWORK
        assert events[0].target == "evil.example"
        assert "1.2.3.4" in events[0].detail

    def test_a_connection_is_reported_as_server_and_port(self):
        events = map_report(
            report_with(
                network={
                    "traffic": [
                        {"server": "185.244.25.14", "port": 443, "proto": "tcp.https"}
                    ]
                }
            ),
            START,
        )

        assert events[0].category == NETWORK
        assert events[0].target == "185.244.25.14:443"


class TestDegradation:
    def test_a_report_with_no_entry_points_yields_no_events_rather_than_raising(self):
        assert map_report({}, START) == []

    def test_an_entry_point_missing_its_sections_does_not_raise(self):
        assert map_report({"entry_points": [{}]}, START) == []

    def test_an_api_entry_without_a_name_is_skipped(self):
        assert map_report({"entry_points": [{"apis": [{}]}]}, START) == []


class TestEmulatingTheBenignFixture:
    def test_the_fixture_emulates_and_the_run_is_marked_complete(self):
        result = detonate_pe(FIXTURE)

        assert result.status == "complete"
        assert result.platform == "windows"
        assert result.engine == "speakeasy"

    def test_the_run_records_how_much_of_the_program_it_covered(self):
        """Speakeasy stops early on unsupported APIs. A report that does not say
        how far emulation got would overstate what was ruled out."""
        result = detonate_pe(FIXTURE)

        assert "410" in result.coverage

    def test_an_emulated_run_is_marked_as_having_no_wall_clock_timing(self):
        """The emulator records the order of calls, not when they happened. The
        timeline must not imply a precision that does not exist."""
        result = detonate_pe(FIXTURE)

        assert result.timed is False

    def test_the_fixture_reads_its_own_file_and_that_is_observed(self):
        result = detonate_pe(FIXTURE)

        assert any(event.category == FILE for event in result.events)

    def test_a_file_that_is_not_a_windows_program_fails_without_raising(self, tmp_path):
        not_a_pe = tmp_path / "notes.txt"
        not_a_pe.write_text("this is not a program")

        result = detonate_pe(not_a_pe)

        assert result.status == "failed"
        assert result.error
        assert result.events == []

    def test_a_failed_run_is_not_treated_as_having_executed_the_sample(self, tmp_path):
        not_a_pe = tmp_path / "notes.txt"
        not_a_pe.write_text("nope")

        assert detonate_pe(not_a_pe).executed is False
