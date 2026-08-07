"""Android detonation.

The hooks run inside the emulator and report over Frida's message channel. What
is tested here is the translation of those messages into behaviour events —
pure, and the part that decides what a report is allowed to claim. Whether the
emulator boots is an environment question, not a logic one, and is verified
separately.
"""

from datetime import datetime, timedelta, timezone

from app.analysis.behavior import DATA_ACCESS, NETWORK
from app.sandbox.android import detonate_apk, event_from_payload, events_from_payloads

START = datetime(2026, 8, 6, 14, 3, 22, tzinfo=timezone.utc)
START_MS = int(START.timestamp() * 1000)


def payload(**overrides):
    base = {
        "ts": START_MS,
        "category": "data-access",
        "action": "read",
        "target": "SMS inbox",
        "detail": "247 records",
    }
    base.update(overrides)
    return base


class TestTranslatingHookMessages:
    def test_a_hook_message_becomes_an_event(self):
        event = event_from_payload(payload(), START)

        assert event.category == DATA_ACCESS
        assert event.action == "read"
        assert event.target == "SMS inbox"
        assert event.detail == "247 records"

    def test_the_hooks_timestamp_sets_the_offset(self):
        event = event_from_payload(payload(ts=START_MS + 3000), START)

        assert event.offset_ms == 3000

    def test_a_message_without_a_timestamp_falls_back_to_the_start(self):
        message = payload()
        del message["ts"]

        assert event_from_payload(message, START).offset_ms == 0

    def test_a_byte_count_is_carried_as_a_number(self):
        event = event_from_payload(
            payload(category="network", action="sent", target="1.2.3.4:443", bytes=34816),
            START,
        )

        assert event.size_bytes == 34816

    def test_every_event_records_that_a_hook_saw_it(self):
        assert event_from_payload(payload(), START).source == "frida"

    def test_an_unrecognised_category_is_rejected(self):
        """The hooks run inside the sandbox alongside the sample. A message is
        untrusted input, and a category the report does not know how to render
        must not reach it."""
        assert event_from_payload(payload(category="totally-made-up"), START) is None

    def test_a_message_without_a_target_is_rejected(self):
        message = payload()
        del message["target"]

        assert event_from_payload(message, START) is None

    def test_a_message_that_is_not_an_object_is_rejected(self):
        assert event_from_payload("not a message", START) is None
        assert event_from_payload(None, START) is None

    def test_a_non_numeric_byte_count_is_dropped_rather_than_guessed(self):
        event = event_from_payload(payload(bytes="lots"), START)

        assert event is not None
        assert event.size_bytes is None

    def test_a_non_numeric_timestamp_falls_back_to_the_start(self):
        assert event_from_payload(payload(ts="soon"), START).offset_ms == 0

    def test_an_overlong_target_is_truncated_rather_than_dropped(self):
        event = event_from_payload(payload(target="h" * 5000), START)

        assert event is not None
        assert len(event.target) < 5000


class TestTranslatingAStream:
    def test_unusable_messages_are_skipped_and_the_rest_survive(self):
        events = events_from_payloads(
            [payload(), "junk", payload(category="nope"), payload(target="contacts")],
            START,
        )

        assert [event.target for event in events] == ["SMS inbox", "contacts"]

    def test_events_come_back_in_the_order_they_happened(self):
        events = events_from_payloads(
            [
                payload(ts=START_MS + 5000, target="second"),
                payload(ts=START_MS + 1000, target="first"),
            ],
            START,
        )

        assert [event.target for event in events] == ["first", "second"]

    def test_a_read_then_a_send_survives_as_the_pairing_the_report_needs(self):
        events = events_from_payloads(
            [
                payload(),
                payload(
                    ts=START_MS + 3000,
                    category="network",
                    action="sent",
                    target="185.244.25.14:443",
                    bytes=34816,
                ),
            ],
            START,
        )

        assert [event.category for event in events] == [DATA_ACCESS, NETWORK]
        assert events[1].offset_ms - events[0].offset_ms == 3000


class TestDegradation:
    def test_a_missing_emulator_fails_the_run_without_raising(self, tmp_path):
        """A sandbox that cannot start costs the report its dynamic section and
        nothing else. The static report still stands."""
        apk = tmp_path / "sample.apk"
        apk.write_bytes(b"PK\x03\x04not really an apk")

        result = detonate_apk(apk, sdk_root=tmp_path / "nonexistent-sdk")

        assert result.status == "failed"
        assert result.error
        assert result.events == []
        assert result.executed is False

    def test_a_missing_file_fails_the_run_without_raising(self, tmp_path):
        result = detonate_apk(tmp_path / "gone.apk", sdk_root=tmp_path)

        assert result.status == "failed"
        assert result.platform == "android"
        assert result.engine == "frida"


class TestTheHookScript:
    def test_the_hook_script_is_shipped_alongside_the_module(self):
        from app.sandbox.android import HOOK_SCRIPT

        assert HOOK_SCRIPT.exists()

    def test_the_hooks_cover_the_behaviour_the_caseload_turns_on(self):
        """Loan-app extortion and OTP theft both start by reading the phone's
        messages and contacts. If a hook for those is dropped the report goes
        quiet on the thing it exists to show."""
        from app.sandbox.android import HOOK_SCRIPT

        source = HOOK_SCRIPT.read_text()

        for target in (
            "ContentResolver",
            "SmsManager",
            "TelephonyManager",
            "LocationManager",
            "DexClassLoader",
        ):
            assert target in source, f"no hook for {target}"


class TestInstrumentationFailure:
    """A hook script that does not run is the most dangerous failure this
    sandbox has. The app launches, behaves normally, and reports nothing — which
    is indistinguishable from an app that did nothing wrong. It must be caught
    and stated, never rendered as an empty timeline."""

    def test_send_messages_are_separated_from_script_errors(self):
        from app.sandbox.android import split_messages

        payloads, errors = split_messages(
            [
                {"type": "send", "payload": {"category": "process"}},
                {"type": "error", "description": "ReferenceError: Java is not defined"},
            ]
        )

        assert payloads == [{"category": "process"}]
        assert errors == ["ReferenceError: Java is not defined"]

    def test_an_error_reports_where_in_the_script_it_happened(self):
        from app.sandbox.android import split_messages

        _, errors = split_messages(
            [{"type": "error", "description": "TypeError: x", "lineNumber": 42}]
        )

        assert "42" in errors[0]

    def test_messages_that_are_neither_are_ignored(self):
        from app.sandbox.android import split_messages

        payloads, errors = split_messages([{"type": "log"}, "junk", None])

        assert payloads == []
        assert errors == []

    def test_a_run_whose_hooks_failed_is_not_reported_as_a_quiet_run(self):
        """If the instrumentation never attached, the correct report is that
        observation failed — not that the app was seen doing nothing."""
        from datetime import datetime, timezone

        from app.sandbox.android import result_from_observation

        result = result_from_observation(
            started_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
            payloads=[],
            errors=["ReferenceError: Java is not defined"],
            artifacts={},
            conditions="ran for 40 seconds",
        )

        assert result.status == "failed"
        assert result.executed is False
        assert "Java is not defined" in result.error

    def test_a_quiet_run_with_working_hooks_is_a_complete_run(self):
        from datetime import datetime, timezone

        from app.sandbox.android import result_from_observation

        result = result_from_observation(
            started_at=datetime(2026, 8, 6, tzinfo=timezone.utc),
            payloads=[],
            errors=[],
            artifacts={},
            conditions="ran for 40 seconds",
        )

        assert result.status == "complete"
        assert result.events == []

    def test_events_still_survive_when_a_later_hook_errors(self):
        """One broken hook must not discard everything the others saw."""
        from datetime import datetime, timezone

        from app.sandbox.android import result_from_observation

        start = datetime(2026, 8, 6, tzinfo=timezone.utc)
        result = result_from_observation(
            started_at=start,
            payloads=[
                {
                    "ts": int(start.timestamp() * 1000),
                    "category": "data-access",
                    "action": "read",
                    "target": "SMS inbox",
                }
            ],
            errors=["TypeError: something in one hook"],
            artifacts={},
            conditions="ran for 40 seconds",
        )

        assert len(result.events) == 1
        assert "TypeError" in result.coverage
        assert result.status == "complete"


class TestDoubleCounting:
    """Android's own framework delegates one `query` call through several
    overloads, so a single read by the app trips the hook more than once. Left
    alone that turns one observation into several, inflates the count of
    exfiltration findings, and puts a number in a police report that is simply
    wrong."""

    def test_the_same_read_reported_twice_in_a_moment_counts_once(self):
        events = events_from_payloads(
            [
                payload(ts=START_MS),
                payload(ts=START_MS + 8),
            ],
            START,
        )

        assert len(events) == 1

    def test_the_surviving_event_is_the_first_one_seen(self):
        events = events_from_payloads(
            [payload(ts=START_MS), payload(ts=START_MS + 8)], START
        )

        assert events[0].offset_ms == 0

    def test_the_same_read_repeated_later_is_a_separate_observation(self):
        """An app that reads the inbox again thirty seconds on really did read
        it twice, and the timeline must show both."""
        events = events_from_payloads(
            [payload(ts=START_MS), payload(ts=START_MS + 30_000)], START
        )

        assert len(events) == 2

    def test_reads_of_different_things_are_never_collapsed(self):
        events = events_from_payloads(
            [
                payload(ts=START_MS, target="SMS inbox"),
                payload(ts=START_MS + 5, target="contacts"),
            ],
            START,
        )

        assert len(events) == 2

    def test_reads_returning_different_counts_are_never_collapsed(self):
        events = events_from_payloads(
            [
                payload(ts=START_MS, detail="247 records"),
                payload(ts=START_MS + 5, detail="88 records"),
            ],
            START,
        )

        assert len(events) == 2


class TestWhenTheClockStarts:
    """Offsets are measured from the moment the app was launched, not from the
    moment the sandbox began. Roughly forty seconds of that is the emulator
    booting, and folding it into the timeline would show an app that read the
    inbox immediately as having waited forty seconds to do it."""

    def test_offsets_are_measured_from_the_launch_not_the_boot(self):
        from app.sandbox.android import result_from_observation

        boot = START
        launch = START + timedelta(seconds=39)
        result = result_from_observation(
            started_at=boot,
            launched_at=launch,
            payloads=[
                payload(ts=int((launch + timedelta(milliseconds=800)).timestamp() * 1000))
            ],
            errors=[],
            artifacts={},
            conditions="ran for 40 seconds",
        )

        assert result.events[0].offset_ms == 800

    def test_the_run_still_records_when_the_sandbox_itself_started(self):
        from app.sandbox.android import result_from_observation

        result = result_from_observation(
            started_at=START,
            launched_at=START + timedelta(seconds=39),
            payloads=[],
            errors=[],
            artifacts={},
            conditions="ran",
        )

        assert result.started_at == START

    def test_without_a_launch_time_the_sandbox_start_is_used(self):
        from app.sandbox.android import result_from_observation

        result = result_from_observation(
            started_at=START,
            payloads=[payload(ts=START_MS + 1500)],
            errors=[],
            artifacts={},
            conditions="ran",
        )

        assert result.events[0].offset_ms == 1500


class TestPickingAFrontDoor:
    """Fraud APKs often hide or omit the LAUNCHER category. Frida's default
    spawn then fails with 'unable to find a front-door activity'. The sandbox
    must still open *some* activity so behaviour can be observed."""

    def test_a_main_activity_is_preferred(self):
        from app.sandbox.android import pick_launch_activity

        chosen = pick_launch_activity(
            "com.smsreceiver.dhruv2",
            [
                "com.smsreceiver.dhruv2.HelperActivity",
                "com.smsreceiver.dhruv2.MainActivity",
            ],
        )

        assert chosen == "com.smsreceiver.dhruv2.MainActivity"

    def test_a_relative_activity_name_is_qualified(self):
        from app.sandbox.android import pick_launch_activity

        assert (
            pick_launch_activity("com.example.app", [".MainActivity"])
            == "com.example.app.MainActivity"
        )

    def test_any_activity_is_used_when_none_looks_like_a_front_door(self):
        from app.sandbox.android import pick_launch_activity

        assert (
            pick_launch_activity("com.example.app", ["com.example.app.Obfuscated"])
            == "com.example.app.Obfuscated"
        )

    def test_an_empty_manifest_yields_nothing(self):
        from app.sandbox.android import pick_launch_activity

        assert pick_launch_activity("com.example.app", []) is None


class TestAdbInstallNaming:
    def test_a_hash_named_sample_is_handed_to_adb_as_an_apk(self, tmp_path, monkeypatch):
        """Samples are stored under their SHA-256 with no extension. adb
        refuses anything that does not end in .apk or .apex, so the install
        step must stage a copy with the right suffix for the duration of the
        push."""
        import subprocess

        from app.sandbox.android import _Emulator, _Tools

        sample = tmp_path / (
            "b1b0c7684bb419d4177eb6e0e5ee7fe7ac6d6ed1b086cfff60ead108b1bc15d0"
        )
        sample.write_bytes(b"PK\x03\x04fake")

        adb = tmp_path / "adb"
        emu_bin = tmp_path / "emulator"
        adb.write_text("#!/bin/sh\n")
        emu_bin.write_text("#!/bin/sh\n")
        adb.chmod(0o755)
        emu_bin.chmod(0o755)

        seen: list[tuple] = []

        def fake_adb(self, *arguments, timeout=120):
            seen.append(arguments)
            return subprocess.CompletedProcess(
                arguments, 0, stdout="Success\n", stderr=""
            )

        monkeypatch.setattr(_Emulator, "_adb", fake_adb)
        error = _Emulator(_Tools(adb, emu_bin), avd="triage").install(sample)

        assert error is None
        assert seen, "adb was never called"
        path_arg = seen[0][-1]
        assert path_arg.endswith(".apk"), path_arg

    def test_a_sample_that_already_ends_in_apk_is_installed_as_itself(
        self, tmp_path, monkeypatch
    ):
        import subprocess

        from app.sandbox.android import _Emulator, _Tools

        sample = tmp_path / "sample.apk"
        sample.write_bytes(b"PK\x03\x04fake")

        adb = tmp_path / "adb"
        emu_bin = tmp_path / "emulator"
        adb.write_text("#!/bin/sh\n")
        emu_bin.write_text("#!/bin/sh\n")
        adb.chmod(0o755)
        emu_bin.chmod(0o755)

        seen: list[tuple] = []

        def fake_adb(self, *arguments, timeout=120):
            seen.append(arguments)
            return subprocess.CompletedProcess(
                arguments, 0, stdout="Success\n", stderr=""
            )

        monkeypatch.setattr(_Emulator, "_adb", fake_adb)
        _Emulator(_Tools(adb, emu_bin), avd="triage").install(sample)

        assert seen[0][-1] == str(sample)
