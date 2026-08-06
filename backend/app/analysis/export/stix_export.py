"""STIX 2.1 bundle export.

Produces a bundle other tools ingest directly, so indicators found here can be
shared with another force or pushed into a threat-intel platform without
retyping. Patterns follow STIX pattern syntax; the sample's own SHA-256 is
included as a file indicator alongside the network indicators.
"""

import json

from stix2 import Bundle, Indicator

from .model import ReportExport

PATTERN_BY_TYPE = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
}


def iocs_to_stix(report: ReportExport) -> str:
    objects = [_file_indicator(report)]

    for indicator in report.indicators:
        template = PATTERN_BY_TYPE.get(indicator.type)
        if template is None:
            continue
        objects.append(_network_indicator(report, indicator, template))

    return Bundle(objects=objects, allow_custom=False).serialize(pretty=True)


def _file_indicator(report: ReportExport) -> Indicator:
    return Indicator(
        name=f"Analysed sample: {report.filename}",
        description=f"Sample assessed as {report.verdict} by static analysis.",
        pattern=f"[file:hashes.'SHA-256' = '{report.sha256}']",
        pattern_type="stix",
        labels=_labels(report.verdict),
    )


def _network_indicator(report: ReportExport, indicator, template: str) -> Indicator:
    description = (
        f"Extracted from {report.filename} (SHA-256 {report.sha256})."
    )
    threatfox = indicator.threatfox
    if threatfox is not None and threatfox.status == "ok":
        family = threatfox.data.get("malware")
        threat_type = threatfox.data.get("threat_type")
        if family:
            description += (
                f" Listed in ThreatFox as {threat_type or 'malicious infrastructure'} "
                f"for {family}."
            )

    return Indicator(
        name=f"{indicator.type} {indicator.value}",
        description=description,
        pattern=template.format(value=indicator.value),
        pattern_type="stix",
        labels=_labels(report.verdict),
    )


def _labels(verdict: str) -> list[str]:
    return ["malicious-activity"] if verdict == "malicious" else ["anomalous-activity"]
