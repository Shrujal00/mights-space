"""The shape both exporters read from."""

from dataclasses import dataclass, field
from datetime import datetime

from ..summary import IndicatorFinding


@dataclass
class ReportExport:
    sha256: str
    filename: str
    verdict: str
    md5: str = ""
    sha1: str = ""
    indicators: list[IndicatorFinding] = field(default_factory=list)
    yara_rules: list[str] = field(default_factory=list)
    analyzed_at: datetime | None = None
