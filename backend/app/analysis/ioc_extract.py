"""Network indicator extraction from recovered strings.

Raw regex extraction over a binary produces mostly noise: every imported DLL
looks like a hostname, every version resource looks like an IPv4 address, and
every signed binary carries certificate-authority URLs. An unfiltered table
buries the two or three indicators an investigator actually needs, so the
filters below matter as much as the patterns.
"""

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address
from typing import Collection, Iterable
from urllib.parse import urlparse
import re


@dataclass(frozen=True)
class Indicator:
    type: str  # "url" | "ipv4" | "domain"
    value: str


URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\)\]}]+", re.IGNORECASE)

# Lookarounds stop the pattern matching inside a longer dotted-numeric run such
# as a four-part file version.
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Vendor and certificate-authority infrastructure. Present in almost every
# signed Windows binary and never an exfiltration destination.
BENIGN_SUFFIXES = frozenset(
    {
        "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
        "msftconnecttest.com", "live.com", "msn.com", "office.com",
        "xmlsoap.org", "w3.org", "opengis.net", "purl.org", "ietf.org",
        "iana.org", "apache.org", "openssl.org", "mozilla.org", "gnu.org",
        "python.org", "oracle.com", "java.com", "sun.com", "adobe.com",
        "verisign.com", "digicert.com", "sectigo.com", "comodoca.com",
        "usertrust.com", "globalsign.com", "entrust.net", "thawte.com",
        "geotrust.com", "symantec.com", "godaddy.com", "letsencrypt.org",
        "certum.pl", "amazontrust.com", "pki.goog", "google.com",
    }
)

# Suffixes that read as a TLD to the regex but are really file extensions.
# A few (.so, .pl, .py, .sh) are genuine country-code TLDs; inside a binary the
# file-extension reading dominates so heavily that excluding them removes far
# more noise than signal. Raw strings remain available in the report.
FILE_EXTENSION_SUFFIXES = frozenset(
    {
        "dll", "exe", "sys", "so", "dylib", "lib", "obj", "pyc", "pyd", "class",
        "jar", "ini", "cfg", "conf", "dat", "tmp", "log", "txt", "xml", "json",
        "yml", "yaml", "toml", "sql", "bak", "swp", "db", "bin", "drv", "ocx",
        "cpl", "msi", "bat", "cmd", "ps1", "vbs", "jse", "php", "asp", "aspx",
        "jsp", "htm", "html", "css", "png", "jpg", "jpeg", "gif", "ico", "cur",
        "bmp", "ttf", "otf", "woff", "res", "rc", "manifest", "mui", "nls",
        "chm", "hlp", "pdb", "inf", "cat", "crl", "cer", "crt", "pem", "zip",
        "rar", "gz", "tar", "cab", "iso", "img", "vhd", "doc", "docx", "xls",
        "xlsx", "ppt", "pptx", "pdf", "rtf", "csv", "md", "lock",
    }
)

# Generic TLDs worth keeping. Any two-letter TLD is a country code and is
# accepted unless it collides with a file extension above.
GENERIC_TLDS = frozenset(
    {
        "com", "org", "net", "int", "edu", "gov", "mil", "arpa", "info", "biz",
        "name", "pro", "mobi", "asia", "tel", "coop", "aero", "jobs", "museum",
        "travel", "xyz", "top", "site", "online", "shop", "store", "club",
        "live", "life", "world", "today", "cloud", "app", "dev", "tech",
        "space", "website", "link", "click", "icu", "buzz", "fun", "cyou",
        "monster", "quest", "rest", "surf", "bar", "best", "digital", "email",
        "host", "network", "one", "press", "services", "solutions", "systems",
        "support", "tools", "vip", "work", "zone", "download", "stream",
    }
)

_TRAILING_PUNCTUATION = ".,;:!?)\"'"


def extract_iocs(
    strings: Iterable[str], exclude: Collection[str] | None = None
) -> list[Indicator]:
    """Extract and filter network indicators, in order of first appearance.

    `exclude` carries values the caller knows are not indicators — chiefly a
    PE's version-resource values, which are bare dotted quads that no pattern
    can tell apart from an address.
    """
    found: dict[Indicator, None] = {}
    excluded = set(exclude or ())

    for text in strings:
        for match in URL_RE.finditer(text):
            url = match.group().rstrip(_TRAILING_PUNCTUATION)
            host = _host_of(url)
            if host and not _host_is_reportable(host):
                continue
            found.setdefault(Indicator("url", url), None)
            if host:
                _record_host(host, found)

        for match in IPV4_RE.finditer(text):
            if _looks_like_a_version(text):
                continue
            if _is_reportable_ip(match.group()):
                found.setdefault(Indicator("ipv4", match.group()), None)

        for match in DOMAIN_RE.finditer(text):
            _record_host(match.group(), found)

    return [indicator for indicator in found if indicator.value not in excluded]


def _host_of(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _record_host(host: str, found: dict[Indicator, None]) -> None:
    host = host.strip(".").lower()
    if _is_ipv4(host):
        if _is_reportable_ip(host):
            found.setdefault(Indicator("ipv4", host), None)
        return
    if _host_is_reportable(host):
        found.setdefault(Indicator("domain", host), None)


def _host_is_reportable(host: str) -> bool:
    host = host.strip(".").lower()
    if _is_ipv4(host):
        return _is_reportable_ip(host)
    if "." not in host:
        return False
    if _is_benign(host):
        return False
    return _has_plausible_tld(host)


def _is_benign(host: str) -> bool:
    return any(
        host == suffix or host.endswith("." + suffix) for suffix in BENIGN_SUFFIXES
    )


def _has_plausible_tld(host: str) -> bool:
    tld = host.rsplit(".", 1)[-1]
    if tld in FILE_EXTENSION_SUFFIXES:
        return False
    return len(tld) == 2 or tld in GENERIC_TLDS


def _is_ipv4(value: str) -> bool:
    try:
        IPv4Address(value)
    except (AddressValueError, ValueError):
        return False
    return True


def _is_reportable_ip(value: str) -> bool:
    """Public, routable addresses only — private and reserved space is noise."""
    try:
        address = IPv4Address(value)
    except (AddressValueError, ValueError):
        return False
    return address.is_global


def _looks_like_a_version(text: str) -> bool:
    """Version resources are the main source of bogus dotted quads in a PE."""
    return "version" in text.lower()
