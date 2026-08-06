"""The shape of an observed behaviour.

Everything else in this project describes what a file *can* do, read out of its
code. This module describes what a sample *did*, recorded while it ran inside a
sandbox. The two must never be conflated in a report: a capability is an
inference, an observation is evidence, and a document that blurs them is a
document a defence lawyer can take apart.

Both sandboxes — the Android emulator and the Windows instruction emulator —
write this same shape, so the correlation, verdict and reporting code downstream
never has to know which one produced an event.

Nothing here touches the sandbox, the database or the clock. It is pure data, so
the reporting logic that depends on it can be tested without detonating
anything.
"""

from dataclasses import dataclass, field
from datetime import datetime

# Event categories. `data-access` is the one that matters most for the caseload
# this system was built for: reading the victim's SMS is the first half of an
# OTP theft, and pairing it with a following `network` event is the second.
PROCESS = "process"
FILE = "file"
NETWORK = "network"
DATA_ACCESS = "data-access"
REGISTRY = "registry"
CRYPTO = "crypto"

CATEGORIES = frozenset({PROCESS, FILE, NETWORK, DATA_ACCESS, REGISTRY, CRYPTO})

# Run outcomes. `timeout` is distinct from `failed` because the sample still
# executed — the observation window simply closed first.
COMPLETE = "complete"
FAILED = "failed"
TIMEOUT = "timeout"

# Outcomes in which the sample actually ran. The report's "was not run" wording
# hangs off this, so it is defined once here rather than re-derived per caller.
_EXECUTED_STATUSES = frozenset({COMPLETE, TIMEOUT})

# The basis recorded against anything derived from a detonation, as opposed to
# the static `static-import` / `static-manifest` bases already in use.
DYNAMIC_BASIS = "dynamic-observed"


@dataclass(frozen=True)
class BehaviorEvent:
    """One thing the sample was observed doing.

    Frozen because these are evidence. Once recorded, an event is not adjusted
    to fit a narrative.
    """

    at: datetime
    offset_ms: int
    category: str
    action: str
    target: str
    detail: str = ""
    source: str = ""
    # Bytes moved, when the engine measured them. Kept as a number rather than
    # folded into `detail` so that the exfiltration total is never recovered by
    # parsing prose — a figure in a police report has to come from the
    # measurement, not from a regular expression over a sentence.
    size_bytes: int | None = None
    # Rows returned by a read, when the engine could count them. None means the
    # count was unavailable, which is not the same as zero: reading the device
    # identifier returns no row count, but it did read something.
    record_count: int | None = None

    @classmethod
    def since(
        cls,
        started_at: datetime,
        at: datetime,
        *,
        category: str,
        action: str,
        target: str,
        detail: str = "",
        source: str = "",
        size_bytes: int | None = None,
        record_count: int | None = None,
    ) -> "BehaviorEvent":
        """Build an event, deriving its offset from the detonation's start.

        The report shows offsets rather than wall-clock times because "three
        seconds after launch" is what a reader can act on. Clocks inside a
        sandbox can also drift behind the host's, so an event that appears to
        precede the start is clamped rather than rendered as a negative offset.
        """
        elapsed = (at - started_at).total_seconds() * 1000
        return cls(
            at=at,
            offset_ms=max(0, int(elapsed)),
            category=category,
            action=action,
            target=target,
            detail=detail,
            source=source,
            size_bytes=size_bytes,
            record_count=record_count,
        )


@dataclass
class DetonationResult:
    """The outcome of running one sample in one sandbox.

    A sandbox never raises at its caller. It returns this, whatever happened, so
    that a sandbox that fails costs the report its dynamic section and nothing
    else — the static analysis still stands on its own.
    """

    platform: str
    engine: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    events: list[BehaviorEvent] = field(default_factory=list)
    error: str = ""
    # Paths to anything the run left on disk (pcap, mitmproxy flows, logcat).
    artifacts: dict[str, str] = field(default_factory=dict)
    # Whether the engine recorded when things happened, or only the order they
    # happened in. The Windows emulator gives sequence alone, so a report built
    # from it must not print gaps between events as though they were measured.
    timed: bool = True
    # How much of the sample was actually observed. A partial run that reads
    # like a complete one invites the reader to conclude too much from silence.
    coverage: str = ""

    @classmethod
    def failed(
        cls,
        *,
        platform: str,
        engine: str,
        started_at: datetime,
        error: str,
        finished_at: datetime | None = None,
        artifacts: dict[str, str] | None = None,
    ) -> "DetonationResult":
        return cls(
            platform=platform,
            engine=engine,
            status=FAILED,
            started_at=started_at,
            finished_at=finished_at,
            events=[],
            error=error,
            artifacts=artifacts or {},
        )

    @property
    def executed(self) -> bool:
        """Whether the sample actually ran.

        This is the single question the report's "the file was not run" note
        depends on. A failed detonation must leave that note intact — nothing
        was observed, so nothing may be claimed as observed.
        """
        return self.status in _EXECUTED_STATUSES
