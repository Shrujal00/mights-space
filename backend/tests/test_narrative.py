import httpx
import respx

from app.analysis.narrative import (
    NarrativeWriter,
    _parse_sections,
    build_facts,
    normalize_model,
)

CHAT_URL = "https://ollama.com/api/chat"
LOCAL_URL = "http://localhost:11434/api/chat"

SECTIONS_JSON = (
    '{"overview": "A Windows program was examined.", '
    '"assessment": "The file is malicious.", '
    '"capabilities": "It is able to record keystrokes.", '
    '"destinations": "It refers to one address.", '
    '"limitations": "The file was not run."}'
)


def reply(content: str, status: int = 200):
    return httpx.Response(status, json={"message": {"content": content}})


def report(**overrides):
    base = {
        "filename": "invoice.exe",
        "detected_type": "PE32 executable",
        "size": 4096,
        "sha256": "a" * 64,
        "verdict": "malicious",
        "headline": "This file is malicious.",
        "reasons": ["45 of 70 antivirus engines identify this file as malicious."],
        "techniques": [],
        "indicators": [],
        "yara": [],
        "files": [],
        "providers": [],
        "warnings": [],
    }
    base.update(overrides)
    return base


class TestModelNaming:
    def test_cloud_suffix_is_dropped_for_the_hosted_api(self):
        # A local daemon pulls cloud models as "<name>-cloud"; ollama.com serves
        # the same model under its bare name and 404s on the suffix.
        assert normalize_model("gemma4:31b-cloud", "https://ollama.com") == "gemma4:31b"

    def test_cloud_suffix_is_kept_for_a_local_daemon(self):
        assert (
            normalize_model("gemma4:31b-cloud", "http://localhost:11434")
            == "gemma4:31b-cloud"
        )

    def test_a_plain_model_name_is_unchanged(self):
        assert normalize_model("gemma4:31b", "https://ollama.com") == "gemma4:31b"


class TestParseSections:
    def test_json_wrapped_in_markdown_fences_is_parsed(self):
        wrapped = f"```json\n{SECTIONS_JSON}\n```"
        sections = _parse_sections(wrapped)
        assert sections["overview"] == "A Windows program was examined."
        assert sections["assessment"] == "The file is malicious."


class TestWhatIsSent:
    def test_the_sample_itself_is_never_transmitted(self):
        # Only findings leave the machine. The file's bytes, its stored path and
        # its raw strings must not appear anywhere in the payload.
        facts = build_facts(report())
        serialized = str(facts)

        assert "storage" not in serialized
        assert "path" not in serialized
        assert facts["sha256"] == "a" * 64

    def test_capabilities_are_labelled_as_static_not_observed(self):
        facts = build_facts(
            report(
                techniques=[
                    {
                        "name": "Screen Capture",
                        "technique_id": "T1113",
                        "plain_language": "Can take pictures of the screen.",
                        "evidence": ["BitBlt"],
                    }
                ]
            )
        )

        assert "not observed" in facts["capabilities_found_in_code"][0]["derived_from"]


class TestWriting:
    @respx.mock
    def test_returns_the_sections_the_model_produced(self):
        respx.post(CHAT_URL).mock(return_value=reply(SECTIONS_JSON))

        result = NarrativeWriter(api_key="key").write(report())

        assert result.status == "ok"
        assert result.sections["assessment"] == "The file is malicious."
        assert result.model == "gemma4:31b"

    @respx.mock
    def test_keys_the_model_invented_are_discarded(self):
        # The document's structure is fixed by our code, not by the model.
        respx.post(CHAT_URL).mock(
            return_value=reply(
                '{"overview": "Fine.", "recommendation": "Arrest the sender."}'
            )
        )

        result = NarrativeWriter(api_key="key").write(report())

        assert set(result.sections) == {"overview"}

    @respx.mock
    def test_offline_mode_makes_no_request(self):
        route = respx.post(CHAT_URL)

        result = NarrativeWriter(api_key="key", offline=True).write(report())

        assert result.status == "skipped"
        assert not route.called

    @respx.mock
    def test_without_a_key_the_hosted_api_is_not_called(self):
        route = respx.post(CHAT_URL)

        result = NarrativeWriter(api_key=None).write(report())

        assert result.status == "skipped"
        assert not route.called

    @respx.mock
    def test_a_local_daemon_needs_no_key(self):
        route = respx.post(LOCAL_URL).mock(return_value=reply(SECTIONS_JSON))

        result = NarrativeWriter(
            api_key=None, host="http://localhost:11434"
        ).write(report())

        assert result.status == "ok"
        assert route.called

    @respx.mock
    def test_a_rejected_key_is_reported_not_raised(self):
        respx.post(CHAT_URL).mock(return_value=httpx.Response(401))

        result = NarrativeWriter(api_key="bad").write(report())

        assert result.status == "unavailable"
        assert "key" in result.detail

    @respx.mock
    def test_a_missing_model_names_the_model_in_the_detail(self):
        respx.post(CHAT_URL).mock(return_value=httpx.Response(404))

        result = NarrativeWriter(api_key="key", model="nope:1b").write(report())

        assert result.status == "unavailable"
        assert "nope:1b" in result.detail

    @respx.mock
    def test_a_timeout_does_not_propagate(self):
        respx.post(CHAT_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))

        assert NarrativeWriter(api_key="key").write(report()).status == "unavailable"

    @respx.mock
    def test_a_reply_that_is_not_json_is_reported_as_unavailable(self):
        # The report must never be blocked by the model returning prose.
        respx.post(CHAT_URL).mock(return_value=reply("Sure! Here is your report:"))

        assert NarrativeWriter(api_key="key").write(report()).status == "unavailable"

    @respx.mock
    def test_the_request_carries_the_bearer_token(self):
        route = respx.post(CHAT_URL).mock(return_value=reply(SECTIONS_JSON))

        NarrativeWriter(api_key="secret-key").write(report())

        assert route.calls.last.request.headers["Authorization"] == "Bearer secret-key"

    @respx.mock
    def test_the_prompt_forbids_claiming_the_file_was_run(self):
        import json

        route = respx.post(CHAT_URL).mock(return_value=reply(SECTIONS_JSON))

        NarrativeWriter(api_key="key").write(report())

        body = json.loads(route.calls.last.request.content)
        system = body["messages"][0]["content"]
        assert "NEVER executed" in system
        assert "safe, clean, harmless" in system


class TestBehaviourReachesTheWriter:
    def _report(self, **overrides):
        run = {
            "platform": "android",
            "engine": "frida",
            "status": "complete",
            "started_at": "2026-08-06T14:03:20+00:00",
            "timed": True,
            "coverage": "The app ran for 45 seconds.",
            "events": [
                {
                    "offset_ms": 2000,
                    "category": "data-access",
                    "action": "read",
                    "target": "SMS inbox",
                    "detail": "247 records",
                    "size_bytes": None,
                }
            ],
            "exfiltration": [
                {
                    "what": "247 records from SMS inbox",
                    "where": "185.244.25.14:443",
                    "gap_ms": 3000,
                    "bytes_sent": 34816,
                    "confidence": "strong",
                }
            ],
        }
        run.update(overrides)
        return {"filename": "yono.apk", "detonations": [run]}

    def test_observed_events_are_given_to_the_writer(self):
        facts = build_facts(self._report())

        assert facts["behaviour_observed_while_running"][0]["did"] == "read"
        assert facts["behaviour_observed_while_running"][0]["to"] == "SMS inbox"

    def test_observed_events_are_labelled_as_observed_not_inferred(self):
        facts = build_facts(self._report())

        assert "observed" in facts["behaviour_observed_while_running"][0]["derived_from"]

    def test_data_seen_leaving_the_device_is_given_to_the_writer(self):
        facts = build_facts(self._report())

        assert facts["data_seen_leaving_the_device"][0]["sent_to"] == "185.244.25.14:443"

    def test_a_static_only_report_gives_the_writer_no_observations(self):
        facts = build_facts({"filename": "invoice.exe"})

        assert facts["behaviour_observed_while_running"] == []
        assert facts["data_seen_leaving_the_device"] == []

    def test_a_failed_detonation_gives_the_writer_no_observations(self):
        """Nothing was seen, so the writer must have nothing to describe as seen."""
        facts = build_facts(self._report(status="failed", events=[], exfiltration=[]))

        assert facts["behaviour_observed_while_running"] == []

    def test_the_writer_is_told_the_file_was_run_and_when(self):
        facts = build_facts(self._report())

        assert facts["was_the_file_run"]["executed"] is True
        assert "2026" in facts["was_the_file_run"]["when"]

    def test_the_writer_is_told_when_the_file_was_not_run(self):
        facts = build_facts({"filename": "invoice.exe"})

        assert facts["was_the_file_run"]["executed"] is False
