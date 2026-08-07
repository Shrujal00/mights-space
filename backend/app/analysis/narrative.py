"""Plain-language report writing via Ollama.

The model is a rewriter, never an analyser. It receives the findings the
deterministic pipeline already produced and turns them into prose an officer can
read; it is given no file, no bytes, and no capacity to add a finding. The
verdict shown in the report always comes from `summary.py`, not from here.

That boundary is enforced in three places: the system prompt forbids new claims,
only already-derived facts are ever sent, and a failure of any kind degrades to
the deterministic narrative rather than blocking the report.

Nothing here sends a sample anywhere. Only the analysis results are transmitted.
"""

from dataclasses import dataclass, field
from typing import Any
import json

import httpx

OK = "ok"
SKIPPED = "skipped"
UNAVAILABLE = "unavailable"

# The order the sections appear in the exported document.
SECTIONS = (
    ("overview", "Overview"),
    ("assessment", "Assessment"),
    ("capabilities", "What this file is able to do"),
    ("destinations", "Network destinations"),
    ("limitations", "Limitations of this analysis"),
)

SYSTEM_PROMPT = """\
You write the narrative section of a static malware analysis report for a police \
cyber unit. The report may be read in court by people with no technical training.

You are given findings that have already been established by automated analysis. \
Your only job is to express those findings in clear English.

Absolute rules:
1. Use ONLY the findings supplied to you. Never add, infer, guess or embellish a \
finding. If a detail is not in the input, it does not go in the report.
2. The file was NEVER executed. Never write that it did something, was seen doing \
something, or was observed behaving in any way. Describe capability only: "is able \
to", "contains code that can".
3. Never state or imply the file is safe, clean, harmless or benign. If nothing was \
found, say that nothing known was found and that this is not proof of safety.
4. Do not recommend actions, name suspects, assign blame, or speculate about who is \
responsible or what their intent was.
5. Plain English. Short sentences. No markdown, no bullet characters, no headings \
inside the values. Expand jargon the first time it appears.
6. If a section has no supporting findings, write one short sentence saying so.

Reply with a single JSON object with exactly these string keys:
"overview", "assessment", "capabilities", "destinations", "limitations".
"""


@dataclass
class NarrativeResult:
    status: str  # ok | skipped | unavailable
    detail: str = ""
    sections: dict[str, str] = field(default_factory=dict)
    model: str = ""


def normalize_model(model: str, host: str) -> str:
    """Match the model name to the endpoint it is being sent to.

    A local Ollama daemon pulls cloud models under a `-cloud` suffix
    (`gemma4:31b-cloud`); ollama.com's own API serves the same model under its
    bare name. Sending the suffixed name to ollama.com is a 404, which is a
    confusing failure for a configuration mistake this easy to make.
    """
    if "ollama.com" in host and model.endswith("-cloud"):
        return model[: -len("-cloud")]
    return model


def build_facts(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce a stored report to the findings the writer is allowed to use."""
    return {
        "file_name": report.get("filename"),
        "file_type": report.get("detected_type"),
        "file_size_bytes": report.get("size"),
        "sha256": report.get("sha256"),
        "verdict": report.get("verdict"),
        "verdict_headline": report.get("headline"),
        "reasons_for_verdict": report.get("reasons") or [],
        "capabilities_found_in_code": [
            {
                "technique": technique.get("name"),
                "mitre_attack_id": technique.get("technique_id"),
                "meaning": technique.get("plain_language"),
                "derived_from": "the file's import table (static, not observed)",
            }
            for technique in report.get("techniques") or []
        ],
        "network_destinations": [
            {
                "kind": indicator.get("type"),
                "value": indicator.get("value"),
                "known_command_and_control_for": (
                    (indicator.get("threatfox") or {}).get("malware")
                ),
                "abuse_confidence_percent": (
                    (indicator.get("abuseipdb") or {}).get("abuse_confidence")
                ),
                "country": (indicator.get("abuseipdb") or {}).get("country"),
            }
            for indicator in report.get("indicators") or []
        ],
        "matched_malware_signatures": [
            hit.get("rule") for hit in report.get("yara") or []
        ],
        "files_contained": [
            {
                "name": leaf.get("relative_name"),
                "type": leaf.get("detected_type"),
                "appears_packed_or_encrypted": leaf.get("likely_packed"),
            }
            for leaf in report.get("files") or []
        ],
        "sources_consulted": [
            {"source": p.get("provider"), "result": p.get("status")}
            for p in report.get("providers") or []
        ],
        "analysis_warnings": report.get("warnings") or [],
        # Dynamic findings are handed over separately from the static ones and
        # labelled at every level, because the writer's whole job is to
        # paraphrase, and a paraphrase that turns "can read messages" into "read
        # messages" would put an unearned claim in a police report.
        "was_the_file_run": _execution_facts(report),
        "behaviour_observed_while_running": [
            {
                "seconds_after_launch": (event.get("offset_ms") or 0) / 1000,
                "kind": event.get("category"),
                "did": event.get("action"),
                "to": event.get("target"),
                "detail": event.get("detail"),
                "bytes": event.get("size_bytes"),
                "derived_from": "observed while the file was running (not inferred)",
            }
            for run in _observed_runs(report)
            for event in run.get("events") or []
        ],
        "data_seen_leaving_the_device": [
            {
                "what_was_read": finding.get("what"),
                "sent_to": finding.get("where"),
                "seconds_later": (
                    finding["gap_ms"] / 1000
                    if isinstance(finding.get("gap_ms"), (int, float))
                    else None
                ),
                "bytes_sent": finding.get("bytes_sent"),
                "confidence": finding.get("confidence"),
                "derived_from": "observed while the file was running (not inferred)",
            }
            for run in _observed_runs(report)
            for finding in run.get("exfiltration") or []
        ],
    }


def _observed_runs(report: dict[str, Any]) -> list[dict]:
    """Only runs in which the sample actually executed.

    A failed detonation observed nothing, so it must contribute nothing the
    writer could describe as having been seen.
    """
    return [
        run
        for run in report.get("detonations") or []
        if run.get("status") in {"complete", "timeout"}
    ]


def _execution_facts(report: dict[str, Any]) -> dict[str, Any]:
    runs = _observed_runs(report)
    if not runs:
        return {
            "executed": False,
            "note": (
                "The file was never run. Describe capabilities only as what the "
                "file is able to do, never as something it did."
            ),
        }
    return {
        "executed": True,
        "when": runs[0].get("started_at"),
        "where": f"a contained {runs[0].get('platform')} sandbox",
        "how_much_was_seen": runs[0].get("coverage"),
    }


class NarrativeWriter:
    def __init__(
        self,
        api_key: str | None = None,
        host: str = "https://ollama.com",
        model: str = "gemma4:31b-cloud",
        timeout: float = 180.0,
        offline: bool = False,
        client: httpx.Client | None = None,
    ):
        self.api_key = api_key
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.offline = offline
        self._client = client

    def write(self, report: dict[str, Any]) -> NarrativeResult:
        if self.offline:
            return NarrativeResult(
                SKIPPED, "offline mode: no narrative was generated"
            )
        # A local Ollama daemon needs no key; ollama.com does.
        if not self.api_key and "ollama.com" in self.host:
            return NarrativeResult(SKIPPED, "no Ollama API key configured")

        model = normalize_model(self.model, self.host)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "Write the report narrative from these findings:\n\n"
                        + json.dumps(build_facts(report), indent=2)
                    ),
                },
            ],
            "stream": False,
            "format": "json",
            # Low temperature: this is a rewriting task, and invention is the
            # failure mode that matters.
            "options": {"temperature": 0.2},
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            response = self._request(
                f"{self.host}/api/chat", payload, headers
            )
        except httpx.HTTPError as exc:
            return NarrativeResult(UNAVAILABLE, f"request failed: {exc}")

        if response.status_code == 401:
            return NarrativeResult(UNAVAILABLE, "Ollama rejected the API key")
        if response.status_code == 404:
            return NarrativeResult(
                UNAVAILABLE, f"model {model!r} is not available on {self.host}"
            )
        if response.status_code != 200:
            return NarrativeResult(UNAVAILABLE, f"HTTP {response.status_code}")

        try:
            content = response.json()["message"]["content"]
        except (ValueError, KeyError, TypeError) as exc:
            return NarrativeResult(UNAVAILABLE, f"unexpected response body: {exc}")

        sections = _parse_sections(content)
        if not sections:
            return NarrativeResult(
                UNAVAILABLE, "the model did not return the expected sections"
            )
        return NarrativeResult(OK, sections=sections, model=model)

    def _request(self, url: str, payload: dict, headers: dict) -> httpx.Response:
        if self._client is not None:
            return self._client.post(url, json=payload, headers=headers)
        with httpx.Client(timeout=self.timeout) as client:
            return client.post(url, json=payload, headers=headers)


def _parse_sections(content: str) -> dict[str, str]:
    """Pull the expected keys out of the model's JSON reply.

    Anything the model added beyond the requested keys is dropped rather than
    rendered — the document's structure is fixed by this code, not by the model.

    Cloud models often wrap JSON in markdown fences even when `format: json` is
    set, so those are stripped before parsing.
    """
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}

    sections: dict[str, str] = {}
    for key, _ in SECTIONS:
        value = parsed.get(key)
        if isinstance(value, str) and value.strip():
            sections[key] = value.strip()
    return sections
