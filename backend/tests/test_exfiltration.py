"""Pairing what the sample read with where it sent it."""

from datetime import datetime, timedelta, timezone

from app.analysis.behavior import DATA_ACCESS, FILE, NETWORK, PROCESS, BehaviorEvent
from app.analysis.exfiltration import DEFAULT_WINDOW_MS, correlate

START = datetime(2026, 8, 6, 14, 3, 22, tzinfo=timezone.utc)


def event(seconds, category, action, target, detail="", size_bytes=None):
    return BehaviorEvent.since(
        START,
        START + timedelta(seconds=seconds),
        category=category,
        action=action,
        target=target,
        detail=detail,
        source="frida",
        size_bytes=size_bytes,
    )


def read_sms(seconds=0.0, detail="247 messages"):
    return event(seconds, DATA_ACCESS, "read", "SMS inbox", detail)


def send(seconds=3.0, target="185.244.25.14:443", size_bytes=34816):
    return event(seconds, NETWORK, "sent", target, size_bytes=size_bytes)


class TestPairing:
    def test_data_read_then_sent_is_reported_as_exfiltration(self):
        findings = correlate([read_sms(), send()])

        assert len(findings) == 1
        assert findings[0].where == "185.244.25.14:443"

    def test_the_finding_names_the_data_that_was_read(self):
        findings = correlate([read_sms(), send()])

        assert "247 messages" in findings[0].what
        assert "SMS inbox" in findings[0].what

    def test_the_finding_records_the_delay_between_reading_and_sending(self):
        findings = correlate([read_sms(seconds=0), send(seconds=3)])

        assert findings[0].gap_ms == 3000

    def test_the_finding_records_how_much_was_sent(self):
        findings = correlate([read_sms(), send(size_bytes=34816)])

        assert findings[0].bytes_sent == 34816

    def test_the_finding_is_timed_from_the_moment_the_data_was_read(self):
        findings = correlate([read_sms(seconds=1), send(seconds=3)])

        assert findings[0].when == START + timedelta(seconds=1)

    def test_reading_alone_is_not_exfiltration(self):
        assert correlate([read_sms()]) == []

    def test_sending_alone_is_not_exfiltration(self):
        assert correlate([send()]) == []

    def test_data_read_after_the_send_is_not_paired_with_it(self):
        """Order is the whole claim. Data read at 14:03:25 cannot have been in a
        transmission that left at 14:03:22."""
        assert correlate([send(seconds=1), read_sms(seconds=3)]) == []

    def test_two_reads_before_one_send_are_both_reported(self):
        findings = correlate(
            [
                read_sms(seconds=0),
                event(1, DATA_ACCESS, "read", "contacts", "88 records"),
                send(seconds=2),
            ]
        )

        assert {finding.what for finding in findings} == {
            "247 messages from SMS inbox",
            "88 records from contacts",
        }

    def test_a_read_pairs_with_the_first_send_that_follows_it(self):
        findings = correlate(
            [
                read_sms(seconds=0),
                send(seconds=1, target="first.example:443"),
                send(seconds=2, target="second.example:443"),
            ]
        )

        assert [finding.where for finding in findings] == ["first.example:443"]

    def test_unrelated_categories_are_ignored(self):
        assert (
            correlate(
                [
                    event(0, PROCESS, "started", "com.example"),
                    event(1, FILE, "wrote", "/data/data/x/cache"),
                ]
            )
            == []
        )


class TestWindow:
    def test_a_send_at_the_edge_of_the_window_still_counts(self):
        findings = correlate([read_sms(seconds=0), send(seconds=DEFAULT_WINDOW_MS / 1000)])

        assert len(findings) == 1

    def test_a_send_past_the_window_does_not_count(self):
        findings = correlate(
            [read_sms(seconds=0), send(seconds=DEFAULT_WINDOW_MS / 1000 + 0.001)]
        )

        assert findings == []

    def test_the_window_can_be_widened(self):
        findings = correlate([read_sms(seconds=0), send(seconds=30)], window_ms=60_000)

        assert len(findings) == 1


class TestConfidence:
    def test_a_measured_gap_supports_a_strong_pairing(self):
        findings = correlate([read_sms(), send()])

        assert findings[0].confidence == "strong"

    def test_without_a_clock_the_pairing_is_only_probable(self):
        """The Windows emulator reports the order of calls but not their timing.
        An unmeasured gap cannot be presented as a measured one."""
        findings = correlate([read_sms(seconds=0), send(seconds=0)], timed=False)

        assert findings[0].confidence == "probable"

    def test_without_a_clock_order_alone_still_pairs_events(self):
        findings = correlate(
            [
                event(0, DATA_ACCESS, "called", "USER32.GetAsyncKeyState"),
                event(0, NETWORK, "connected", "1.2.3.4:80"),
            ],
            timed=False,
        )

        assert len(findings) == 1

    def test_without_a_clock_no_gap_is_reported(self):
        findings = correlate([read_sms(seconds=0), send(seconds=0)], timed=False)

        assert findings[0].gap_ms is None


class TestReadsThatFoundNothing:
    """An app that queries an empty contacts list and then sends something has
    not exfiltrated contacts. Reporting "0 records from contacts" as data sent
    out of the device would put a theft in the report that never happened."""

    def test_a_read_that_returned_no_rows_is_not_exfiltration(self):
        empty = BehaviorEvent.since(
            START,
            START,
            category=DATA_ACCESS,
            action="read",
            target="contacts",
            detail="0 records",
            record_count=0,
        )

        assert correlate([empty, send()]) == []

    def test_a_read_that_returned_rows_is_still_exfiltration(self):
        found = BehaviorEvent.since(
            START,
            START,
            category=DATA_ACCESS,
            action="read",
            target="SMS inbox",
            detail="247 records",
            record_count=247,
        )

        assert len(correlate([found, send()])) == 1

    def test_a_read_with_no_count_available_is_still_exfiltration(self):
        """Reading the device identifier returns no row count at all. Absence of
        a count is not evidence that nothing was read."""
        assert len(correlate([read_sms(), send()])) == 1
