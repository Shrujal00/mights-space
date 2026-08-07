"""Verdict assignment and plain-language reporting.

This module produces the part of the report a non-technical officer actually
reads, so two rules govern it:

1. The verdict is deterministic and rule-based. The same findings always give
   the same answer, and every verdict carries the specific reasons behind it.
2. It never states or implies that a file is harmless. Static analysis can show
   that something bad is present; it cannot show that nothing bad is present.
   An "unknown" result says exactly that, because the reader may act on it.

Nothing is ever executed, so every capability is phrased as what the file *can*
do, never as behaviour that was observed.
"""

from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv6Address

from .attack_map import Technique
from .behavior import NETWORK, DetonationResult
from .exfiltration import ExfiltrationFinding
from .pe_analysis import PackingAssessment
from .reputation.base import ProviderResult

MALICIOUS_DETECTION_THRESHOLD = 5
ABUSE_CONFIDENCE_THRESHOLD = 50

MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
UNKNOWN = "unknown"

_LEVEL_ORDER = {UNKNOWN: 0, SUSPICIOUS: 1, MALICIOUS: 2}

HEADLINES = {
    MALICIOUS: "This file is malicious.",
    SUSPICIOUS: "This file is suspicious and needs closer examination.",
    UNKNOWN: "No known indicators of compromise were found in this file.",
}

NOT_EXECUTED_NOTE = (
    "The file was not run at any point during this analysis. Everything above "
    "describes what the file is able to do, based on reading its code — not "
    "behaviour that was observed."
)

# Said instead of NOT_EXECUTED_NOTE once a sample has actually been detonated.
# The note is made conditional rather than removed: most reports are still
# static-only, and for those the original sentence remains true and important.
EXECUTED_NOTE = (
    "The file was run on {when} inside a contained Android sandbox — an isolated "
    "virtual phone holding no real accounts, contacts or personal data. Anything "
    "described above as observed was recorded there as it happened."
)

EMULATED_NOTE = (
    "The file was run on {when} inside an emulated Windows sandbox. Its "
    "instructions were carried out by a simulated processor against a simulated "
    "copy of Windows, so its code never ran on a real computer at any point. "
    "Anything described above as observed was recorded there as it happened."
)

UNKNOWN_CAVEAT = (
    "This is not proof that the file is harmless. It may be too new to have been "
    "reported yet, or targeted enough that no one has submitted it before."
)


@dataclass
class IndicatorFinding:
    type: str
    value: str
    threatfox: ProviderResult | None = None
    abuseipdb: ProviderResult | None = None
    urlscan: ProviderResult | None = None


@dataclass
class SampleFindings:
    filename: str = "sample.bin"
    file_type: str = "data"
    yara_rules: list[str] = field(default_factory=list)
    techniques: list[Technique] = field(default_factory=list)
    indicators: list[IndicatorFinding] = field(default_factory=list)
    virustotal: ProviderResult | None = None
    malwarebazaar: ProviderResult | None = None
    packing: PackingAssessment | None = None
    # Android impersonation tells, as (code, plain language) pairs.
    android_signals: list[tuple[str, str]] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    # Dynamic analysis. `detonation` is None for a static-only report, which is
    # still the normal case; `exfiltration` is empty unless a sandbox observed
    # data being read and then sent.
    detonation: DetonationResult | None = None
    exfiltration: list[ExfiltrationFinding] = field(default_factory=list)


@dataclass
class Summary:
    level: str
    headline: str
    narrative: str
    reasons: list[str]
    capabilities: list[str]
    destinations: list[str]


def summarize(findings: SampleFindings) -> Summary:
    level = UNKNOWN
    reasons: list[str] = []

    def raise_to(new_level: str) -> None:
        nonlocal level
        if _LEVEL_ORDER[new_level] > _LEVEL_ORDER[level]:
            level = new_level

    for reason, signal in _antivirus_signals(findings.virustotal):
        reasons.append(reason)
        raise_to(signal)

    for reason, signal in _database_signals(findings.malwarebazaar):
        reasons.append(reason)
        raise_to(signal)

    for reason, signal in _destination_signals(findings.indicators):
        reasons.append(reason)
        raise_to(signal)

    for reason, signal in _exfiltration_signals(findings):
        reasons.append(reason)
        raise_to(signal)

    for reason, signal in _observed_network_signals(findings):
        reasons.append(reason)
        raise_to(signal)

    if findings.yara_rules:
        reasons.append(
            f"The file matched {len(findings.yara_rules)} known malware signature(s): "
            f"{', '.join(findings.yara_rules)}."
        )
        raise_to(SUSPICIOUS)

    for reason, signal in _impersonation_signals(findings):
        reasons.append(reason)
        raise_to(signal)

    if findings.packing and findings.packing.likely_packed:
        reasons.append(
            "The file's contents appear to be packed or encrypted to conceal what "
            "the program does, a technique commonly used to evade antivirus software."
        )
        raise_to(SUSPICIOUS)

    capabilities = [technique.plain_language for technique in findings.techniques]
    destinations = [indicator.value for indicator in findings.indicators]

    return Summary(
        level=level,
        headline=HEADLINES[level],
        narrative=_build_narrative(findings, level, reasons, capabilities, destinations),
        reasons=reasons,
        capabilities=capabilities,
        destinations=destinations,
    )


def _antivirus_signals(result: ProviderResult | None):
    if not result or result.status != "ok":
        return
    detections = result.data.get("malicious", 0)
    total = result.data.get("total_engines", 0)
    if detections >= MALICIOUS_DETECTION_THRESHOLD:
        label = result.data.get("threat_label")
        described_as = f", identifying it as {label}" if label else ""
        yield (
            f"{detections} of {total} antivirus engines identify this file as "
            f"malicious{described_as}.",
            MALICIOUS,
        )
    elif detections >= 1:
        yield (
            f"{detections} of {total} antivirus engines flagged this file, which is "
            "few enough that it may be a false alarm.",
            SUSPICIOUS,
        )


def _database_signals(result: ProviderResult | None):
    if not result or result.status != "ok":
        return
    signature = result.data.get("signature") or "a known malware family"
    yield (
        f"This exact file is recorded in the MalwareBazaar malware database as "
        f"{signature}.",
        MALICIOUS,
    )


def _destination_signals(indicators: list[IndicatorFinding]):
    for indicator in indicators:
        threatfox = indicator.threatfox
        if threatfox and threatfox.status == "ok":
            family = threatfox.data.get("malware") or "a known malware family"
            yield (
                f"{indicator.value} is a known command-and-control server used by "
                f"{family}, meaning stolen data would be sent there.",
                MALICIOUS,
            )

        abuseipdb = indicator.abuseipdb
        if abuseipdb and abuseipdb.status == "ok":
            score = abuseipdb.data.get("abuse_confidence", 0)
            if score >= ABUSE_CONFIDENCE_THRESHOLD:
                country = abuseipdb.data.get("country")
                located = f" (hosted in {country})" if country else ""
                yield (
                    f"{indicator.value}{located} has been reported for malicious "
                    f"activity by other victims, with {score}% confidence.",
                    SUSPICIOUS,
                )


_OUTBOUND_NETWORK_ACTIONS = frozenset({"connected", "opened", "sent", "looked up"})
_INBOUND_NETWORK_ACTIONS = frozenset({"recv", "received", "read"})


def _observed_network_signals(findings: SampleFindings):
    """Contact with a remote host while the sample ran.

    Exfiltration pairings remain the strongest mobile-fraud signal. These rules
    catch command-and-control style traffic that never paired a read with a send.
    """
    detonation = findings.detonation
    if detonation is None or not detonation.executed:
        return

    known_servers = {
        indicator.value: indicator.threatfox.data.get("malware") or "a known malware family"
        for indicator in findings.indicators
        if indicator.threatfox and indicator.threatfox.status == "ok"
    }

    by_host = _network_activity_by_host(detonation.events)

    for host, info in by_host.items():
        if not info["outbound"]:
            continue

        targets = info["targets"]
        assert isinstance(targets, set)
        target = max(targets, key=len) if targets else host
        family = known_servers.get(host)
        private = _is_private_host(host)

        if family is not None:
            yield (
                f"The file was observed contacting {target} inside the sandbox. "
                f"That address is a known command-and-control server used by "
                f"{family}.",
                MALICIOUS,
            )
        elif info["inbound"] and not private:
            yield (
                f"The file was observed opening a connection to {target} and "
                f"receiving data back, consistent with remote command-and-control.",
                MALICIOUS,
            )
        elif info["inbound"] and private:
            yield (
                f"The file was observed opening a two-way connection to {target} "
                f"inside the sandbox — the pattern remote-control malware uses so "
                f"an attacker can run commands on the machine. The address is on a "
                f"private lab network, so this is treated as suspicious rather than "
                f"confirmed command-and-control.",
                SUSPICIOUS,
            )
        elif not private:
            yield (
                f"The file was observed contacting {target} inside the sandbox.",
                SUSPICIOUS,
            )


def _network_activity_by_host(events) -> dict[str, dict[str, set[str] | bool]]:
    by_host: dict[str, dict[str, set[str] | bool]] = {}
    for event in events:
        if event.category != NETWORK:
            continue

        host = _address_of(event.target)
        slot = by_host.setdefault(host, {"outbound": False, "inbound": False, "targets": set()})
        targets = slot["targets"]
        assert isinstance(targets, set)
        targets.add(event.target)

        action = event.action.lower()
        if action in _OUTBOUND_NETWORK_ACTIONS:
            slot["outbound"] = True
        if action in _INBOUND_NETWORK_ACTIONS:
            slot["inbound"] = True
    return by_host


def _is_private_host(host: str) -> bool:
    """Lab, loopback, and link-local space never justify a verdict on their own."""
    for parser in (IPv4Address, IPv6Address):
        try:
            return not parser(host).is_global
        except (AddressValueError, ValueError):
            continue
    return False


def _exfiltration_signals(findings: SampleFindings):
    """Data seen leaving the device.

    This is the strongest evidence the system can produce, because it is the
    only part of the report describing something that happened rather than
    something that could. The wording says "was observed" everywhere, so that a
    reader skimming the reasons cannot mistake it for an inference drawn from
    the code.
    """
    known_servers = {
        indicator.value: indicator.threatfox.data.get("malware")
        or "a known malware family"
        for indicator in findings.indicators
        if indicator.threatfox and indicator.threatfox.status == "ok"
    }

    for finding in findings.exfiltration:
        taken = f"The app was observed reading {finding.what} and sending data to "
        moved = _describe_volume(finding.bytes_sent)
        family = known_servers.get(_address_of(finding.where))

        if family is not None:
            yield (
                f"{taken}{finding.where}{_describe_gap(finding.gap_ms)}"
                f"{moved}. That address is a known command-and-control server "
                f"used by {family}, so the data went to the attacker.",
                MALICIOUS,
            )
        else:
            yield (
                f"{taken}{finding.where}{_describe_gap(finding.gap_ms)}{moved}.",
                SUSPICIOUS,
            )


def _address_of(destination: str) -> str:
    """The bare address from an observed `host:port`.

    Threat intelligence is keyed on the address alone, while an observation
    always carries the port it was seen on. Without this the strongest evidence
    in the report would silently fail to match a known server.
    """
    host, separator, port = destination.rpartition(":")
    if separator and port.isdigit():
        return host.strip("[]")
    return destination


def _describe_gap(gap_ms: int | None) -> str:
    """How long after the read the transmission left, when it was measured."""
    if gap_ms is None:
        return ""
    if gap_ms < 1000:
        return f" {gap_ms} milliseconds later"
    return f" {gap_ms / 1000:.1f} seconds later"


def _describe_volume(bytes_sent: int | None) -> str:
    if not bytes_sent:
        return ""
    if bytes_sent < 1024:
        return f", {bytes_sent} bytes in total"
    return f", {bytes_sent / 1024:.0f} KB in total"


# Tells that establish the app is pretending to be something else, rather than
# merely looking unusual.
_IMPERSONATION_CODES = frozenset(
    {
        "brand-impersonation",
        "vendor-namespace-abuse",
        "self-describing-package",
        "invisible-characters",
    }
)

_SMS_TECHNIQUES = frozenset({"T1636.004", "T1582", "T1517"})


def _impersonation_signals(findings: SampleFindings):
    """Android fraud tells, and the one combination that is conclusive.

    An app disguised as a bank is suspicious. An app disguised as a bank that can
    also read the phone's text messages is the standard construction of an
    OTP-theft kit: the disguise gets it installed, the SMS access takes the
    one-time code. Neither half alone justifies the top verdict; together they
    leave nothing else to explain.
    """
    impersonating = [
        (code, description)
        for code, description in findings.android_signals
        if code in _IMPERSONATION_CODES
    ]

    for _, description in findings.android_signals:
        yield description, SUSPICIOUS

    reads_messages = any(
        technique.technique_id in _SMS_TECHNIQUES for technique in findings.techniques
    )
    if impersonating and reads_messages:
        yield (
            "The app disguises itself as a trusted organisation and can also read "
            "the phone's text messages. Together these are how a one-time passcode "
            "is intercepted to authorise a payment the victim did not make.",
            MALICIOUS,
        )


def _build_narrative(
    findings: SampleFindings,
    level: str,
    reasons: list[str],
    capabilities: list[str],
    destinations: list[str],
) -> str:
    sections = [
        f"{findings.filename} ({findings.file_type})",
        HEADLINES[level],
    ]

    if reasons:
        sections.append(" ".join(reasons))

    if capabilities:
        listed = "; ".join(capability.rstrip(".") for capability in capabilities)
        sections.append(f"Looking at the code inside the file, it is able to: {listed}.")

    if destinations:
        sections.append(
            f"The file refers to {len(destinations)} internet "
            f"{'address' if len(destinations) == 1 else 'addresses'}: "
            f"{', '.join(destinations)}."
        )

    if level == UNKNOWN:
        sections.append(UNKNOWN_CAVEAT)

    sections.append(_execution_note(findings.detonation))
    return "\n\n".join(sections)


def _execution_note(detonation: DetonationResult | None) -> str:
    """Whether the file was run, and if so where and when.

    A failed or missing detonation keeps the original wording: nothing was
    observed, so nothing may be presented as observed. Only a run that actually
    executed the sample earns the note that says so.
    """
    if detonation is None or not detonation.executed:
        return NOT_EXECUTED_NOTE

    started = detonation.started_at
    when = started.strftime("%d %B %Y at %H:%M:%S UTC") if started else "an unrecorded date"
    template = EMULATED_NOTE if detonation.platform == "windows" else EXECUTED_NOTE
    return template.format(when=when)
