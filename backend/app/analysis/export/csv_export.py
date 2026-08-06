"""CSV export of indicators.

Every row carries the sample hash so rows stay meaningful after the file is
opened in a spreadsheet, merged with another case, or pasted into an email.
Columns are always written even when empty, so the shape does not change
between reports.
"""

import csv
import io

from .model import ReportExport

COLUMNS = [
    "sample_sha256",
    "sample_filename",
    "sample_verdict",
    "indicator_type",
    "indicator_value",
    "threatfox_malware",
    "threatfox_threat_type",
    "abuseipdb_confidence",
    "abuseipdb_country",
    "urlscan_results",
]


def iocs_to_csv(report: ReportExport) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()

    for indicator in report.indicators:
        threatfox = _data(indicator.threatfox)
        abuseipdb = _data(indicator.abuseipdb)
        urlscan = _data(indicator.urlscan)
        writer.writerow(
            {
                "sample_sha256": report.sha256,
                "sample_filename": report.filename,
                "sample_verdict": report.verdict,
                "indicator_type": indicator.type,
                "indicator_value": indicator.value,
                "threatfox_malware": threatfox.get("malware", ""),
                "threatfox_threat_type": threatfox.get("threat_type", ""),
                "abuseipdb_confidence": abuseipdb.get("abuse_confidence", ""),
                "abuseipdb_country": abuseipdb.get("country", ""),
                "urlscan_results": urlscan.get("result_count", ""),
            }
        )

    return output.getvalue()


def _data(result) -> dict:
    """Provider payload, or empty when the provider was skipped or failed."""
    if result is None or result.status != "ok":
        return {}
    return {key: ("" if value is None else value) for key, value in result.data.items()}
