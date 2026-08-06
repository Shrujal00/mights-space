"""Printable-string recovery from raw sample bytes.

Covers both ASCII and UTF-16LE. Windows binaries store most of their strings as
UTF-16LE, where an ASCII-only scan sees single characters separated by NUL bytes
and recovers nothing — so an ASCII-only pass silently loses most of the URLs and
hostnames in a PE sample.
"""

import re

PRINTABLE = rb"[\x20-\x7e]"

# Categories of string worth putting in front of an investigator. A modern APK
# carries tens of thousands of strings and a raw dump is unreadable, so the
# report shows the ones that suggest what the sample is *for* — and says which
# category each fell into, so the reader knows why it is listed.
NOTABLE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "Command and control",
        "an address or endpoint the sample may contact",
        re.compile(r"(?:https?://|ftp://|/gate\.php|/panel/|/api/|/bot|\.onion)", re.I),
    ),
    (
        "Messaging channel",
        "chat services are commonly used to receive stolen data",
        re.compile(r"(?:t\.me/|api\.telegram\.org|chat_id|sendMessage|discord\.com/api/webhooks)", re.I),
    ),
    (
        "Credentials",
        "the sample refers to secrets or authentication material",
        re.compile(r"(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|credential)", re.I),
    ),
    (
        "One-time codes",
        "references to passcodes used to authorise payments",
        # Underscore is a word character, so \b fails on the identifiers these
        # actually appear in ("otp_received", "smsReceiver"). Letter lookarounds
        # match the segment wherever it sits.
        re.compile(
            r"(?:(?<![a-z])otp(?![a-z])|one[_-]?time|verification[_-]?code"
            r"|(?<![a-z])sms|inbox)",
            re.I,
        ),
    ),
    (
        "Command execution",
        "the sample refers to running system commands",
        re.compile(r"(?:cmd\.exe|powershell|/system/bin/sh|\bsu -c\b|pm install|Runtime\.exec)", re.I),
    ),
    (
        "Concealment",
        "encryption or encoding used to hide the sample's contents",
        re.compile(r"(?:base64|AES/|DESede|javax\.crypto|XOR key)", re.I),
    ),
    (
        "Sensitive location",
        "paths where personal data or system files are kept",
        re.compile(r"(?:/data/data/|/sdcard/|%APPDATA%|C:\\\\Windows\\\\|/etc/passwd)", re.I),
    ),
)

MIN_NOTABLE_LENGTH = 6
MAX_NOTABLE_LENGTH = 300


def extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Return deduplicated printable strings, in order of first appearance."""
    ascii_pattern = re.compile(PRINTABLE + rb"{%d,}" % min_length)
    utf16_pattern = re.compile(rb"(?:" + PRINTABLE + rb"\x00){%d,}" % min_length)

    found: dict[str, None] = {}
    for match in ascii_pattern.finditer(data):
        found.setdefault(match.group().decode("ascii"), None)
    for match in utf16_pattern.finditer(data):
        found.setdefault(match.group().decode("utf-16-le"), None)

    return list(found)


def select_notable(
    strings: list[str], limit: int = 300
) -> list[dict[str, str]]:
    """Pick out the strings that say something about the sample's purpose.

    Returns `{value, category, why}` in order of first appearance. The category
    is what makes this usable in a report: an investigator needs to know why a
    string was surfaced, not just that it was.
    """
    selected: dict[str, dict[str, str]] = {}

    for text in strings:
        if not (MIN_NOTABLE_LENGTH <= len(text) <= MAX_NOTABLE_LENGTH):
            continue
        for category, why, pattern in NOTABLE_PATTERNS:
            if pattern.search(text):
                selected.setdefault(
                    text, {"value": text, "category": category, "why": why}
                )
                break
        if len(selected) >= limit:
            break

    return list(selected.values())
