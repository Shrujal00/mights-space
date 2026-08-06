"""Android APK static inspection.

Mirrors `pe_analysis.py` for the Android side: parse, never execute. The manifest
gives the permissions an app requests and the components it exposes; the DEX gives
the framework classes its code refers to and the string pool its URLs live in.

One thing here has no Windows equivalent and matters a great deal. An APK is a
ZIP, and `classes.dex` inside it is deflated. Running the ordinary string scanner
over APK bytes recovers nothing but compression noise, so every embedded URL and
C2 address would be silently lost. The DEX string pool is therefore extracted
here and handed back for the IOC extractor to work on.

Input is hostile: malware ships deliberately malformed manifests and ZIP records
to break analysis tools. Every stage is contained so a broken APK degrades to a
partial report rather than taking down the pipeline.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import hashlib
import zipfile

from androguard.core.apk import APK
from androguard.core.dex import DEX

from .android_map import dangerous, high_abuse
from .apk_signals import Signal, assess_apk

# Guards against a crafted app with a pathological string pool.
MAX_DEX_STRINGS = 200_000
MAX_STRING_LENGTH = 4096


@dataclass
class CertificateInfo:
    subject: str
    issuer: str
    sha256: str
    not_before: datetime | None = None
    not_after: datetime | None = None

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer


@dataclass
class ApkReport:
    package: str = ""
    app_label: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str | None = None
    target_sdk: str | None = None

    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    high_abuse_permissions: list[str] = field(default_factory=list)

    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)

    is_signed: bool = False
    certificates: list[CertificateInfo] = field(default_factory=list)
    native_libraries: list[str] = field(default_factory=list)

    # Recovered from the decompressed DEX, not from the APK's raw bytes.
    dex_strings: list[str] = field(default_factory=list)
    api_markers: list[str] = field(default_factory=list)

    # Impersonation and evasion tells — see apk_signals.py.
    signals: list[Signal] = field(default_factory=list)

    warnings: list[str] = field(default_factory=list)


def is_apk(path: Path) -> bool:
    """True for a ZIP carrying the two files every Android package must have.

    Checked by name rather than by parsing, so this stays cheap enough to run on
    every uploaded file and cannot be tripped by a malformed manifest.
    """
    path = Path(path)
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return False
    return "AndroidManifest.xml" in names and any(
        name.startswith("classes") and name.endswith(".dex") for name in names
    )


def analyze_apk(path: Path) -> ApkReport:
    """Parse an APK. Never raises: a broken package yields a partial report."""
    report = ApkReport()
    try:
        apk = APK(str(path))
    except Exception as exc:  # noqa: BLE001 - androguard raises many types
        report.warnings.append(f"the Android manifest could not be parsed: {exc}")
        return report

    _read_manifest(apk, report)
    _read_certificates(apk, report)
    _read_dex(apk, report)
    report.signals = assess_apk(
        report.package,
        report.app_label,
        [certificate.subject for certificate in report.certificates],
    )
    return report


def _read_manifest(apk: APK, report: ApkReport) -> None:
    try:
        report.package = apk.get_package() or ""
        report.app_label = _safe(apk.get_app_name)
        report.version_name = str(apk.get_androidversion_name() or "")
        report.version_code = str(apk.get_androidversion_code() or "")
        report.min_sdk = _optional(apk.get_min_sdk_version)
        report.target_sdk = _optional(apk.get_target_sdk_version)

        permissions = sorted(set(apk.get_permissions() or []))
        report.permissions = permissions
        report.dangerous_permissions = dangerous(permissions)
        report.high_abuse_permissions = high_abuse(permissions)

        report.activities = sorted(set(apk.get_activities() or []))
        report.services = sorted(set(apk.get_services() or []))
        report.receivers = sorted(set(apk.get_receivers() or []))
        report.providers = sorted(set(apk.get_providers() or []))
        report.native_libraries = sorted(set(apk.get_libraries() or []))
    except Exception as exc:  # noqa: BLE001
        report.warnings.append(f"the manifest was only partly readable: {exc}")


def _read_certificates(apk: APK, report: ApkReport) -> None:
    """Signing certificate.

    A self-signed certificate proves nothing on its own — every Android app is
    self-signed — but the fingerprint is what links separately-named apps from
    the same campaign, which is the useful part for an investigator.
    """
    try:
        report.is_signed = bool(apk.is_signed())
        for der in apk.get_certificates_der_v2() + apk.get_certificates_der_v3():
            report.certificates.append(_certificate(der))
        if not report.certificates:
            for der in apk.get_certificates_der_v1():
                report.certificates.append(_certificate(der))
    except Exception as exc:  # noqa: BLE001
        report.warnings.append(f"the signing certificate could not be read: {exc}")


def _certificate(der: bytes) -> CertificateInfo:
    from asn1crypto import x509

    parsed = x509.Certificate.load(der)
    return CertificateInfo(
        subject=parsed.subject.human_friendly,
        issuer=parsed.issuer.human_friendly,
        sha256=hashlib.sha256(der).hexdigest(),
        not_before=parsed["tbs_certificate"]["validity"]["not_before"].native,
        not_after=parsed["tbs_certificate"]["validity"]["not_after"].native,
    )


def _read_dex(apk: APK, report: ApkReport) -> None:
    """Pull the string pool out of every DEX in the package.

    Multi-dex apps carry classes.dex, classes2.dex and so on; missing the later
    ones loses whole libraries, so all of them are read.
    """
    strings: dict[str, None] = {}
    try:
        for dex_bytes in apk.get_all_dex():
            try:
                for value in DEX(dex_bytes).get_strings():
                    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
                    if len(text) <= MAX_STRING_LENGTH:
                        strings.setdefault(text, None)
                    if len(strings) >= MAX_DEX_STRINGS:
                        report.warnings.append(
                            f"the app contains more than {MAX_DEX_STRINGS:,} strings; "
                            "only the first were examined"
                        )
                        raise _StringBudgetReached
            except _StringBudgetReached:
                break
            except Exception as exc:  # noqa: BLE001
                report.warnings.append(f"one code section could not be read: {exc}")
    except Exception as exc:  # noqa: BLE001
        report.warnings.append(f"the app's code could not be read: {exc}")

    report.dex_strings = list(strings)
    # The pool holds type descriptors and method names alongside literals, so the
    # capability markers are matched against the same list.
    report.api_markers = report.dex_strings


class _StringBudgetReached(Exception):
    pass


def _safe(getter) -> str:
    try:
        return str(getter() or "")
    except Exception:  # noqa: BLE001
        return ""


def _optional(getter) -> str | None:
    try:
        value = getter()
        return str(value) if value is not None else None
    except Exception:  # noqa: BLE001
        return None
