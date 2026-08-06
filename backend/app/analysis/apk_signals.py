"""Fraud tells specific to Android impersonation campaigns.

The permission map answers "what can this app do". These answer a different and
often more decisive question: "is this app pretending to be something it is not".

Every heuristic here came from looking at real samples from Indian fraud
campaigns — fake bank KYC updates, RTO e-Challan notices, gas-bill apps. The
pattern is always the same: the app wears a trusted name and the package
underneath does not match it. A human notices instantly, and no permission
analysis catches it at all.

These are indicators, not proof. Each returns the specific evidence behind it so
the report can show its working.
"""

from dataclasses import dataclass
import re
import unicodedata

# Characters with no visible width. Legitimate app names do not contain them;
# fraud apps use them to break exact-match searching and blocklists, and to make
# two different names look identical on screen.
INVISIBLE = frozenset(
    "​‌‍‎‏⁠⁡⁢⁣⁤"
    "﻿­؜᠎‪‫‬‭‮"
)

# The debug keystore Android SDK tools generate. Real publishers sign with their
# own key; this subject means the package was built and shipped without one.
DEBUG_CERT_MARKERS = ("Common Name: Android", "Organization: Google")

# brand term -> package fragments the genuine publisher actually uses
TRUSTED_BRANDS: dict[str, tuple[str, ...]] = {
    "sbi": ("com.sbi", "org.sbi"),
    "yono": ("com.sbi",),
    "bank of baroda": ("com.bankofbaroda",),
    "baroda": ("com.bankofbaroda",),
    "union bank": ("com.unionbank", "com.infrasofttech"),
    "unionbank": ("com.unionbank", "com.infrasofttech"),
    # Banks' app names differ from the bank's name, and fraud apps copy the app
    # name rather than the bank's — so the product names have to be listed too.
    "vyom": ("com.unionbank", "com.infrasofttech"),
    "imobile": ("com.csam.icici", "com.icicibank"),
    "imobile pay": ("com.csam.icici", "com.icicibank"),
    "hdfc": ("com.snapwork.hdfc", "com.hdfcbank"),
    "icici": ("com.csam.icici", "com.icicibank"),
    "axis": ("com.axis",),
    "kotak": ("com.msf.kbank", "com.kotak"),
    "punjab national": ("com.Version1", "com.pnb"),
    "canara": ("com.canarabank",),
    "paytm": ("net.one97.paytm",),
    "phonepe": ("com.phonepe",),
    "google pay": ("com.google.android.apps.nbu",),
    "whatsapp": ("com.whatsapp",),
    "rto": ("com.nic", "gov.in"),
    "echallan": ("com.nic", "gov.in"),
    "e-challan": ("com.nic", "gov.in"),
    "parivahan": ("com.nic",),
    "aadhaar": ("in.gov.uidai",),
    "digilocker": ("com.digilocker",),
    "income tax": ("com.incometax", "gov.in"),
    "igl": ("com.igl", "co.in"),
    "mgl": ("com.mahanagar", "co.in"),
    "adani": ("com.adani",),
    "tata power": ("com.tatapower",),
}

# Package prefixes belonging to major vendors. A package claiming one of these
# while carrying an unrelated app name is impersonating the vendor's namespace.
VENDOR_NAMESPACES = {
    "com.google.": "Google",
    "com.facebook.": "Facebook",
    "com.tencent.": "Tencent",
    "com.whatsapp": "WhatsApp",
    "com.instagram.": "Instagram",
    "com.microsoft.": "Microsoft",
    "com.android.": "Android system",
}

# Package names that read as machine-generated rather than chosen.
RANDOM_SEGMENT = re.compile(r"^[a-z]{5,12}$")

# Ordinary words that appear in real package names and must not be mistaken for
# generated noise.
COMMON_SEGMENTS = frozenset(
    {
        "system", "service", "services", "secure", "security", "android",
        "mobile", "client", "server", "update", "manager", "player", "reader",
        "wallet", "banking", "finance", "market", "store", "cloud", "studio",
        "digital", "network", "connect", "assist", "support", "health",
    }
)

# A package that names the thing it steals. Fraud kits are built quickly and
# their authors rarely bother to disguise the module names.
SUSPICIOUS_PACKAGE_TERMS = (
    "smsreceiver", "smsreceive", "smsforward", "smssteal", "readsms",
    "otpread", "otpsteal", "otpforward", "stealer", "spyapp", "ratclient",
    "keylog", "hiddenapp", "cardsteal",
)


@dataclass(frozen=True)
class Signal:
    code: str
    plain_language: str
    detail: str


def invisible_characters(label: str) -> Signal | None:
    found = sorted({ch for ch in label if ch in INVISIBLE})
    if not found:
        return None
    names = ", ".join(
        unicodedata.name(ch, f"U+{ord(ch):04X}").title() for ch in found[:4]
    )
    return Signal(
        "invisible-characters",
        "The app's name contains hidden characters that do not appear on screen. "
        "Legitimate apps do not do this; it is used to disguise the name and "
        "evade searches.",
        f"{len(found)} kind(s) of invisible character in the name: {names}",
    )


def brand_impersonation(package: str, label: str) -> Signal | None:
    """App carries a trusted name while its package belongs to no such publisher."""
    haystack = _visible(label).lower()
    package_lower = package.lower()

    for brand, legitimate in TRUSTED_BRANDS.items():
        if brand not in haystack:
            continue
        if any(fragment.lower() in package_lower for fragment in legitimate):
            return None  # name and publisher agree
        return Signal(
            "brand-impersonation",
            f"The app presents itself as \"{_visible(label)}\" but it was not "
            f"published by that organisation. Its internal package name is "
            f"\"{package}\", which does not belong to them.",
            f"label matches trusted brand {brand!r}; package {package!r} does not "
            f"match any of {legitimate}",
        )
    return None


def vendor_namespace_abuse(package: str, label: str) -> Signal | None:
    """Package sits in a major vendor's namespace without being their app."""
    package_lower = package.lower()
    for prefix, vendor in VENDOR_NAMESPACES.items():
        if not package_lower.startswith(prefix):
            continue
        if vendor.lower() in _visible(label).lower():
            return None
        return Signal(
            "vendor-namespace-abuse",
            f"The app's internal package name claims to be a {vendor} app, but "
            f"the app itself is presented as \"{_visible(label) or 'unnamed'}\". "
            "Genuine apps do not use another company's package name.",
            f"package {package!r} occupies the {vendor} namespace {prefix!r}",
        )
    return None


def debug_certificate(certificate_subjects: list[str]) -> Signal | None:
    for subject in certificate_subjects:
        if all(marker in subject for marker in DEBUG_CERT_MARKERS):
            return Signal(
                "debug-certificate",
                "The app is signed with the default test certificate that comes "
                "with Android development tools, rather than a publisher's own "
                "signing key. No legitimate published app is signed this way.",
                f"certificate subject: {subject}",
            )
    return None


def generated_package_name(package: str) -> Signal | None:
    """Package built from meaningless segments, e.g. com.fvotnk.android."""
    segments = package.split(".")
    if len(segments) < 2:
        return None
    middle = segments[1:-1] if len(segments) > 2 else segments[1:]
    suspicious = [
        segment
        for segment in middle
        if RANDOM_SEGMENT.match(segment)
        and segment not in COMMON_SEGMENTS
        and not _pronounceable(segment)
    ]
    if not suspicious:
        return None
    return Signal(
        "generated-package-name",
        "The app's internal package name looks automatically generated rather "
        "than chosen, which is common in apps produced in bulk by a kit.",
        f"unpronounceable segment(s): {', '.join(suspicious)}",
    )


def self_describing_package(package: str) -> Signal | None:
    """Package name that states what the app is for, e.g. com.smsreceiver.x."""
    lowered = package.lower().replace("_", "")
    matched = [term for term in SUSPICIOUS_PACKAGE_TERMS if term in lowered]
    if not matched:
        return None
    return Signal(
        "self-describing-package",
        "The app's internal package name describes intercepting messages or "
        "stealing credentials. A legitimate app's package name describes the "
        "app, not that.",
        f"package {package!r} contains: {', '.join(matched)}",
    )


def assess_apk(
    package: str,
    label: str,
    certificate_subjects: list[str] | None = None,
) -> list[Signal]:
    """All impersonation and evasion tells found for one package."""
    candidates = [
        invisible_characters(label or ""),
        brand_impersonation(package or "", label or ""),
        vendor_namespace_abuse(package or "", label or ""),
        self_describing_package(package or ""),
        debug_certificate(certificate_subjects or []),
        generated_package_name(package or ""),
    ]
    return [signal for signal in candidates if signal is not None]


def _visible(text: str) -> str:
    return "".join(ch for ch in text if ch not in INVISIBLE).strip()


def _pronounceable(segment: str) -> bool:
    """Rough test for a word-like segment: real words carry enough vowels.

    'y' counts — without it 'system' and 'crypty' read as generated noise.
    """
    vowels = sum(1 for ch in segment if ch in "aeiouy")
    if vowels == 0:
        return False
    # "fvotnk" has one vowel in six characters; "android" has three in seven.
    return vowels / len(segment) >= 0.25
