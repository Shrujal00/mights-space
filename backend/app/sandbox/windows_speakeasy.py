"""Windows behaviour by emulation, not execution.

Speakeasy runs a PE's instructions on an emulated CPU against a synthetic
Windows kernel. The sample's code never reaches the host processor and the
"filesystem" and "network" it touches do not exist, so there is no host to
escape to. For a report that has to be defensible, this is a stronger claim than
a virtual machine: it is not that the sample was contained, it is that it was
never really running.

The trade-off is coverage. Emulation stops at the first API Speakeasy does not
implement, and packed samples often stop early. Every run therefore records how
far it got, so the report can say what was and was not observed rather than
implying a clean bill of health.

Speakeasy is imported inside the functions that need it, never at module level.
Importing it pulls in unicorn, which imports the deprecated `pkg_resources` and
emits a warning; the test suite runs with `filterwarnings = error`, so a
top-level import here would fail the entire suite on collection.
"""

import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..analysis.attack_map import TECHNIQUE_SIGNATURES, normalize_import
from ..analysis.behavior import (
    COMPLETE,
    CRYPTO,
    DATA_ACCESS,
    FILE,
    NETWORK,
    PROCESS,
    REGISTRY,
    BehaviorEvent,
    DetonationResult,
)

WINDOWS = "windows"
SPEAKEASY = "speakeasy"

# Which kind of behaviour each capability represents. The technique catalogue is
# shared with the static import mapper, so a program that *imports*
# CreateRemoteThread and a program observed *calling* it are described in the
# same words — while remaining distinguishable by `basis`.
_TECHNIQUE_CATEGORY = {
    "T1056.001": DATA_ACCESS,  # keylogging reads what the victim types
    "T1055": PROCESS,
    "T1113": DATA_ACCESS,  # screen capture reads what the victim sees
    "T1071": NETWORK,
    "T1105": NETWORK,
    "T1547.001": REGISTRY,
    "T1057": PROCESS,
    "T1082": DATA_ACCESS,  # collecting machine details is data gathering
    "T1123": DATA_ACCESS,
    "T1486": CRYPTO,
}

# Reverse index from a triggering API name to its technique, built once.
_TRIGGER_TO_TECHNIQUE = {
    trigger: technique_id
    for technique_id, (_, _, triggers) in TECHNIQUE_SIGNATURES.items()
    for trigger in triggers
}


def detonate_pe(path: Path | str, on_progress=None) -> DetonationResult:
    """Emulate one Windows program and report what it did.

    Never raises. A sample that will not load, or that crashes the emulator,
    comes back as a failed run so the static report it belongs to still stands.
    """
    started_at = datetime.now(timezone.utc)

    def say(message: str) -> None:
        """Report a stage. Progress reporting must never break a run."""
        if on_progress is None:
            return
        try:
            on_progress(message)
        except Exception:  # noqa: BLE001
            pass

    def failure(error: str) -> DetonationResult:
        return DetonationResult.failed(
            platform=WINDOWS,
            engine=SPEAKEASY,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            error=error,
        )

    say("Loading the program into an emulated computer")

    with _third_party_warnings_contained():
        try:
            speakeasy = _import_speakeasy()
            emulator = speakeasy.Speakeasy()
            module = emulator.load_module(str(path))
        except Exception as exc:  # noqa: BLE001 - a sandbox reports, never raises
            return failure(f"the file could not be loaded as a Windows program: {exc}")

        say("Running its instructions on a simulated processor")
        stopped_by = ""
        try:
            emulator.run_module(module)
        except Exception as exc:  # noqa: BLE001 - stopping early is the normal case
            stopped_by = f"{type(exc).__name__}: {exc}"

        try:
            report = emulator.get_report()
        except Exception as exc:  # noqa: BLE001
            return failure(f"the emulator produced no report: {exc}")

    say("Matching what it did against known techniques")

    return DetonationResult(
        platform=WINDOWS,
        engine=SPEAKEASY,
        status=COMPLETE,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        events=map_report(report, started_at),
        # Emulation gives the order of calls and nothing more. Saying so here
        # keeps the timeline from implying a precision it does not have.
        timed=False,
        coverage=_describe_coverage(report, stopped_by),
    )


@contextmanager
def _third_party_warnings_contained():
    """Keep Speakeasy's own deprecation warnings out of the caller's filters.

    Two of them bite. Importing unicorn warns about `pkg_resources`, and
    Speakeasy calls the deprecated `datetime.utcnow()` while emulating. The test
    suite runs with `filterwarnings = error`, so either one would surface as an
    exception — the second mid-emulation, silently truncating a trace to zero
    calls and making a sample look inert when it was not.

    Scoped to this module's calls into Speakeasy, so warnings from our own code
    are still errors everywhere else.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        yield


def _import_speakeasy():
    import speakeasy

    return speakeasy


def _describe_coverage(report: dict, stopped_by: str) -> str:
    """How much of the program was actually emulated.

    A partial trace that reads as a complete one is the failure mode that
    matters here: it invites the reader to conclude that nothing else happens.
    """
    calls = sum(
        len(entry.get("apis") or []) for entry in report.get("entry_points") or []
    )
    described = f"Emulation traced {calls} Windows API call(s)."

    errors = [
        entry.get("error", {}).get("type")
        for entry in report.get("entry_points") or []
        if entry.get("error")
    ]
    if stopped_by:
        return f"{described} Emulation stopped early: {stopped_by}."
    if errors:
        return f"{described} Emulation stopped early: {', '.join(filter(None, errors))}."
    return f"{described} The program ran to its end inside the emulator."


def map_report(report: dict, started_at: datetime) -> list[BehaviorEvent]:
    """Turn an emulator report into behaviour events.

    Pure, and tolerant of missing keys: the report shape varies with how far
    emulation got, and a truncated report must still yield whatever it holds.
    """
    events: list[BehaviorEvent] = []
    for entry in report.get("entry_points") or []:
        if not isinstance(entry, dict):
            continue
        events.extend(_api_events(entry, started_at))
        events.extend(_file_events(entry, started_at))
        events.extend(_network_events(entry, started_at))
    return events


def _api_events(entry: dict, started_at: datetime) -> list[BehaviorEvent]:
    """Meaningful API calls only, collapsed to one event per distinct call.

    A trace is overwhelmingly C-runtime bookkeeping — sixty `TlsGetValue` calls
    for every interesting one. Only calls that map to a known capability are
    reported, and repeats are counted rather than listed, so the timeline stays
    readable by the officer who has to act on it.
    """
    counted: dict[str, int] = {}
    for call in entry.get("apis") or []:
        name = call.get("api_name") if isinstance(call, dict) else None
        if not name or _technique_for(name) is None:
            continue
        counted[name] = counted.get(name, 0) + 1

    events = []
    for name, count in counted.items():
        _, plain_language, _ = TECHNIQUE_SIGNATURES[_technique_for(name)]
        repeated = f" Called {count} times." if count > 1 else ""
        events.append(
            BehaviorEvent.since(
                started_at,
                started_at,
                category=_TECHNIQUE_CATEGORY[_technique_for(name)],
                action="called",
                target=name,
                detail=f"{plain_language}{repeated}",
                source=SPEAKEASY,
            )
        )
    return events


def _technique_for(api_name: str) -> str | None:
    """The capability a traced call implies, if any.

    Speakeasy reports calls as `MODULE.Function`; the static mapper knows only
    the function, and Windows appends an ANSI/wide suffix to most string APIs.
    Both are stripped before the lookup.
    """
    function = api_name.rsplit(".", 1)[-1]
    return _TRIGGER_TO_TECHNIQUE.get(normalize_import(function))


def _file_events(entry: dict, started_at: datetime) -> list[BehaviorEvent]:
    events = []
    for access in entry.get("file_access") or []:
        if not isinstance(access, dict) or not access.get("path"):
            continue
        size = access.get("size")
        events.append(
            BehaviorEvent.since(
                started_at,
                started_at,
                category=FILE,
                action=access.get("event") or "access",
                target=access["path"],
                detail=f"{size} bytes" if size else "",
                source=SPEAKEASY,
            )
        )
    return events


def _network_events(entry: dict, started_at: datetime) -> list[BehaviorEvent]:
    traffic = entry.get("network_events") or {}
    if not isinstance(traffic, dict):
        return []

    events = []
    for query in traffic.get("dns") or []:
        if not isinstance(query, dict) or not query.get("query"):
            continue
        response = query.get("response")
        events.append(
            BehaviorEvent.since(
                started_at,
                started_at,
                category=NETWORK,
                action="looked up",
                target=query["query"],
                detail=f"resolved to {response}" if response else "",
                source=SPEAKEASY,
            )
        )

    for connection in traffic.get("traffic") or []:
        if not isinstance(connection, dict) or not connection.get("server"):
            continue
        server, port = connection["server"], connection.get("port")
        events.append(
            BehaviorEvent.since(
                started_at,
                started_at,
                category=NETWORK,
                action="connected",
                target=f"{server}:{port}" if port else server,
                detail=" ".join(
                    part
                    for part in (connection.get("method"), connection.get("proto"))
                    if part
                ),
                source=SPEAKEASY,
            )
        )
    return events
