"""Pairing data the sample read with data it sent.

This is the finding the whole dynamic pipeline exists to produce. On its own,
"the app read the SMS inbox" is a capability an SMS client also has, and "the
app contacted an address" is something every app does. Put in order and close
together in time, they stop being ambiguous:

    read 247 messages from the SMS inbox at 14:03:22
    sent 34 KB to 185.244.25.14 three seconds later

The pairing is a correlation, not a proof that those exact bytes were those
exact messages — nothing short of decrypting the traffic would show that. So a
finding reports the observations and the gap between them and lets the reader
weigh it, rather than asserting a causal link the evidence does not carry.

Pure. Takes events, returns findings, touches nothing.
"""

from dataclasses import dataclass
from datetime import datetime

from .behavior import DATA_ACCESS, NETWORK, BehaviorEvent

# How long after a read a transmission can still plausibly carry what was read.
# Five seconds is a starting point, chosen to be short enough that ordinary
# background traffic does not sweep up every read that preceded it.
DEFAULT_WINDOW_MS = 5_000

STRONG = "strong"
PROBABLE = "probable"


@dataclass(frozen=True)
class ExfiltrationFinding:
    what: str
    where: str
    when: datetime
    # None when the engine had no clock: absent, not zero.
    gap_ms: int | None
    bytes_sent: int | None
    confidence: str


def correlate(
    events: list[BehaviorEvent],
    *,
    window_ms: int = DEFAULT_WINDOW_MS,
    timed: bool = True,
) -> list[ExfiltrationFinding]:
    """Pair each read of victim data with the first transmission that follows.

    `timed=False` for engines that record the order of events but not when they
    happened — the Windows instruction emulator. Ordering alone still pairs the
    events, but the gap is reported as absent and the finding is only probable,
    because an unmeasured interval must not be printed as a measured one.
    """
    findings = []

    for index, source_event in enumerate(events):
        if source_event.category != DATA_ACCESS:
            continue
        # A query that came back empty took nothing, so nothing could have left
        # with it. Reporting it would place a theft in the document that did not
        # happen. A missing count is not the same as a count of zero, and does
        # not disqualify the pairing.
        if source_event.record_count == 0:
            continue

        destination = _first_transmission_after(
            events, index, source_event, window_ms, timed
        )
        if destination is None:
            continue

        findings.append(
            ExfiltrationFinding(
                what=_describe(source_event),
                where=destination.target,
                when=source_event.at,
                gap_ms=(
                    destination.offset_ms - source_event.offset_ms if timed else None
                ),
                bytes_sent=destination.size_bytes,
                confidence=STRONG if timed else PROBABLE,
            )
        )

    return findings


def _first_transmission_after(
    events: list[BehaviorEvent],
    index: int,
    source_event: BehaviorEvent,
    window_ms: int,
    timed: bool,
) -> BehaviorEvent | None:
    """The first network event following a read, within the window.

    Only the first: a read that pairs with every later transmission would turn
    one observation into a list of destinations the evidence does not support.
    """
    for candidate in events[index + 1 :]:
        if candidate.category != NETWORK:
            continue
        if timed and candidate.offset_ms - source_event.offset_ms > window_ms:
            return None
        return candidate
    return None


def _describe(event: BehaviorEvent) -> str:
    """What was read, in the words the report will use."""
    if event.detail:
        return f"{event.detail} from {event.target}"
    return event.target
