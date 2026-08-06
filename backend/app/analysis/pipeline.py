"""Static analysis orchestrator.

Takes one uploaded file and walks it through every analyser: hash it, expand it
if it is an archive, then for each resulting file run signature matching, PE
inspection, string and indicator extraction, and capability mapping. The
aggregate is enriched against threat intelligence and reduced to a verdict and a
plain-language summary.

No sample is executed at any point. Everything here reads bytes.
"""

from dataclasses import dataclass, field
from pathlib import Path

from .android_map import map_android_to_techniques
from .apk_analysis import ApkReport, analyze_apk, is_apk
from .attack_map import Technique, map_imports_to_techniques
from .extract import ExtractionLimits, detect_file_type, extract_sample
from .hashing import hash_file
from .ioc_extract import Indicator, extract_iocs
from .pe_analysis import PeReport, analyze_pe, is_pe
from .reputation.base import ProviderResult
from .strings_extract import extract_strings, select_notable
from .summary import IndicatorFinding, SampleFindings, Summary, summarize
from .yara_scan import YaraMatch, YaraScanner

# Strings are recovered from an in-memory copy, so very large files are read up
# to this point only. Hashing and YARA still cover the whole file.
MAX_STRING_SCAN_BYTES = 64 * 1024 * 1024


@dataclass
class LeafReport:
    relative_name: str
    sha256: str
    detected_type: str
    size: int
    yara: list[YaraMatch] = field(default_factory=list)
    pe: PeReport | None = None
    apk: ApkReport | None = None
    techniques: list[Technique] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    notable_strings: list[dict] = field(default_factory=list)


@dataclass
class PipelineResult:
    filename: str
    sha256: str
    md5: str
    sha1: str
    size: int
    detected_type: str
    files: list[LeafReport]
    warnings: list[str]
    indicators: list[IndicatorFinding]
    techniques: list[Technique]
    yara_rules: list[str]
    summary: Summary
    provider_statuses: list[ProviderResult]
    # The inputs the verdict was reached from. Kept so that if the sample is
    # later detonated, the summary can be recomputed from the static findings
    # plus what was observed, rather than the two being reconciled after the
    # fact.
    findings: SampleFindings


def analyze_sample(
    path: Path,
    original_filename: str,
    *,
    scanner: YaraScanner,
    enricher,
    workdir: Path,
    limits: ExtractionLimits | None = None,
) -> PipelineResult:
    path, workdir = Path(path), Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    digests = hash_file(path)
    extraction = extract_sample(path, workdir, limits)

    leaves = [_analyze_leaf(item, scanner) for item in extraction.files]

    indicators = _unique_indicators(leaves)
    techniques = _merge_techniques(leaves)
    yara_rules = _unique_yara_rules(leaves)

    hash_results = enricher.enrich_hash(digests["sha256"])
    enriched = enricher.enrich_indicators(indicators)

    findings = SampleFindings(
        filename=original_filename,
        file_type=extraction.detected_type,
        yara_rules=yara_rules,
        techniques=techniques,
        indicators=enriched,
        virustotal=hash_results.get("virustotal"),
        malwarebazaar=hash_results.get("malwarebazaar"),
        packing=_first_packing(leaves),
        android_signals=_android_signals(leaves),
        dangerous_permissions=_dangerous_permissions(leaves),
    )

    return PipelineResult(
        filename=original_filename,
        sha256=digests["sha256"],
        md5=digests["md5"],
        sha1=digests["sha1"],
        size=path.stat().st_size,
        detected_type=extraction.detected_type,
        files=leaves,
        warnings=extraction.warnings,
        indicators=enriched,
        techniques=techniques,
        yara_rules=yara_rules,
        summary=summarize(findings),
        provider_statuses=_provider_statuses(hash_results, enriched),
        findings=findings,
    )


def _analyze_leaf(item, scanner: YaraScanner) -> LeafReport:
    digests = hash_file(item.path)

    apk_report = analyze_apk(item.path) if is_apk(item.path) else None
    pe_report = (
        analyze_pe(item.path) if apk_report is None and is_pe(item.path) else None
    )

    strings, techniques, exclude = _inspect(item, apk_report, pe_report)

    return LeafReport(
        relative_name=item.relative_name,
        sha256=digests["sha256"],
        detected_type=detect_file_type(item.path),
        size=item.path.stat().st_size,
        yara=scanner.scan_file(item.path, filename=item.relative_name),
        pe=pe_report,
        apk=apk_report,
        techniques=techniques,
        indicators=extract_iocs(strings, exclude=exclude),
        # The spec asks for suspicious strings, not every string: a modern APK
        # carries tens of thousands and a raw dump helps nobody.
        notable_strings=select_notable(strings),
    )


def _inspect(item, apk_report: ApkReport | None, pe_report: PeReport | None):
    """Strings, capabilities and IOC exclusions for one file, by format."""
    if apk_report is not None:
        # Reading the APK's own bytes would scan compressed ZIP members and
        # recover nothing, so the strings come from the decompressed DEX.
        return (
            apk_report.dex_strings,
            map_android_to_techniques(apk_report.permissions, apk_report.api_markers),
            None,
        )

    with open(item.path, "rb") as handle:
        data = handle.read(MAX_STRING_SCAN_BYTES)

    if pe_report is not None:
        return (
            extract_strings(data),
            map_imports_to_techniques(pe_report.imported_functions),
            # A PE's own version numbers are bare dotted quads; without this the
            # report lists them as exfiltration destinations.
            pe_report.version_strings,
        )

    return extract_strings(data), [], None


def _unique_indicators(leaves: list[LeafReport]) -> list[Indicator]:
    seen: dict[Indicator, None] = {}
    for leaf in leaves:
        for indicator in leaf.indicators:
            seen.setdefault(indicator, None)
    return list(seen)


def _merge_techniques(leaves: list[LeafReport]) -> list[Technique]:
    merged: dict[str, Technique] = {}
    for leaf in leaves:
        for technique in leaf.techniques:
            existing = merged.get(technique.technique_id)
            if existing is None:
                merged[technique.technique_id] = technique
            else:
                combined = tuple(dict.fromkeys(existing.evidence + technique.evidence))
                merged[technique.technique_id] = Technique(
                    existing.technique_id,
                    existing.name,
                    existing.plain_language,
                    combined,
                )
    return list(merged.values())


def _unique_yara_rules(leaves: list[LeafReport]) -> list[str]:
    seen: dict[str, None] = {}
    for leaf in leaves:
        for match in leaf.yara:
            seen.setdefault(match.rule, None)
    return list(seen)


def _android_signals(leaves: list[LeafReport]) -> list[tuple[str, str]]:
    seen: dict[str, str] = {}
    for leaf in leaves:
        if leaf.apk is None:
            continue
        for signal in leaf.apk.signals:
            seen.setdefault(signal.code, signal.plain_language)
    return list(seen.items())


def _dangerous_permissions(leaves: list[LeafReport]) -> list[str]:
    seen: dict[str, None] = {}
    for leaf in leaves:
        if leaf.apk is None:
            continue
        for permission in leaf.apk.dangerous_permissions:
            seen.setdefault(permission, None)
    return list(seen)


def _first_packing(leaves: list[LeafReport]):
    for leaf in leaves:
        if leaf.pe is not None:
            return leaf.pe.packing
    return None


def _provider_statuses(
    hash_results: dict[str, ProviderResult], enriched: list[IndicatorFinding]
) -> list[ProviderResult]:
    statuses = list(hash_results.values())
    for finding in enriched:
        statuses.extend(
            result
            for result in (finding.threatfox, finding.abuseipdb, finding.urlscan)
            if result is not None
        )
    return statuses
