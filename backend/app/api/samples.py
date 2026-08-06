"""Sample upload, report retrieval and IOC export."""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from ..analysis.behavior import DYNAMIC_BASIS, BehaviorEvent, DetonationResult
from ..analysis.exfiltration import correlate
from ..analysis.export.csv_export import iocs_to_csv
from ..analysis.export.docx_export import report_to_docx
from ..analysis.export.model import ReportExport
from ..analysis.export.stix_export import iocs_to_stix
from ..analysis.hashing import hash_bytes
from ..analysis.narrative import NarrativeResult
from ..analysis.pipeline import analyze_sample
from ..analysis.reputation.base import ProviderResult
from ..analysis.summary import IndicatorFinding, summarize
from ..detonation import append_progress, finish_run, record_run, start_run
from ..models import AttackTechnique, Ioc, LeafFile, ProviderStatus, Sample, YaraHit

router = APIRouter(prefix="/api/samples", tags=["samples"])


@router.post("", status_code=201)
async def upload_sample(
    request: Request,
    background: BackgroundTasks,
    file: UploadFile = File(...),
):
    state = request.app.state
    content = await file.read()

    if not content:
        raise HTTPException(status_code=400, detail="uploaded file is empty")
    if len(content) > state.settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="uploaded file is too large")

    digests = hash_bytes(content)
    filename = Path(file.filename or "sample.bin").name

    with state.database.session() as session:
        existing = (
            session.query(Sample).filter(Sample.sha256 == digests["sha256"]).one_or_none()
        )
        if existing is not None:
            # Same bytes, same analysis. Re-running would spend rate-limited
            # lookups to reach the same answer.
            return {
                "id": existing.id,
                "sha256": existing.sha256,
                "status": existing.status,
                "duplicate": True,
            }

        storage_dir = Path(state.settings.sample_storage_dir)
        storage_dir.mkdir(parents=True, exist_ok=True)
        stored_path = storage_dir / digests["sha256"]
        stored_path.write_bytes(content)

        sample = Sample(
            sha256=digests["sha256"],
            md5=digests["md5"],
            sha1=digests["sha1"],
            filename=filename,
            size=len(content),
            status="queued",
        )
        session.add(sample)
        session.commit()
        sample_id = sample.id

    background.add_task(run_analysis, request.app, sample_id, stored_path, filename)

    return {
        "id": sample_id,
        "sha256": digests["sha256"],
        "status": "queued",
        "duplicate": False,
    }


def run_analysis(app, sample_id: int, path: Path, filename: str) -> None:
    """Analyse a stored sample and persist the report.

    Any failure is recorded on the sample rather than raised, so a file that
    defeats one analyser still leaves the investigator with a report.
    """
    state = app.state
    result = None
    with state.database.session() as session:
        sample = session.get(Sample, sample_id)
        if sample is None:
            return
        try:
            result = analyze_sample(
                path,
                filename,
                scanner=state.scanner,
                enricher=state.enricher,
                workdir=Path(state.settings.sample_storage_dir) / f"work-{sample_id}",
            )
            _persist(session, sample, result)
            sample.status = "complete"
        except Exception as exc:  # noqa: BLE001 - report failures, never crash
            result = None
            sample.status = "failed"
            sample.error = f"{type(exc).__name__}: {exc}"
        sample.completed_at = datetime.now(timezone.utc)
        session.commit()

    # The static report is committed and readable before the sandbox is asked
    # for anything. Detonation takes minutes, and an investigator should not be
    # made to wait on it for findings that are already final.
    #
    # Only automatic when the deployment is configured for it. Otherwise running
    # the file is a deliberate step the investigator asks for, which is the
    # safer default: it executes the sample, and only one can run at a time.
    detonator = getattr(app.state, "detonator", None)
    if result is not None and detonator is not None and detonator.applies(result):
        run_detonation(app, sample_id, path, result)


@router.post("/{sample_id}/detonate", status_code=202)
def detonate(request: Request, background: BackgroundTasks, sample_id: int):
    """Send a already-examined sample to the sandbox to be run.

    Separate from upload on purpose. This is the point at which the file stops
    being read and starts being executed, and an investigator should be the one
    to decide that.
    """
    state = request.app.state
    detonator = getattr(state, "detonator", None)

    with state.database.session() as session:
        sample = _load(session, sample_id)
        if sample.status != "complete":
            raise HTTPException(
                status_code=409,
                detail="this file has not finished being examined yet",
            )
        if any(run.status == "running" for run in sample.detonations):
            raise HTTPException(
                status_code=409, detail="this file is already running in the sandbox"
            )
        stored = Path(state.settings.sample_storage_dir) / sample.sha256

    result = _rebuild_pipeline_result(state, stored, sample_id)
    if detonator is None or not detonator.can_run(result):
        raise HTTPException(
            status_code=409,
            detail=(
                "no sandbox is configured on this server for this kind of file, "
                "so it cannot be run"
            ),
        )

    background.add_task(run_detonation, request.app, sample_id, stored, result)
    return {"id": sample_id, "status": "detonating"}


def _rebuild_pipeline_result(state, path: Path, sample_id: int):
    """Re-derive the static findings a detonation needs to build on.

    Re-analysing is cheap next to booting an emulator, and it keeps the verdict
    recomputation working from the same `SampleFindings` the first pass used
    rather than from a partially reconstructed copy.
    """
    return analyze_sample(
        path,
        path.name,
        scanner=state.scanner,
        enricher=state.enricher,
        workdir=Path(state.settings.sample_storage_dir) / f"work-{sample_id}",
    )


def run_detonation(app, sample_id: int, path: Path, result) -> None:
    """Run the sample in a sandbox and fold what it did into its report.

    No failure here may cost the report. A sandbox that will not start, or one
    that falls over mid-run, leaves the static findings exactly as they were.

    The run is opened on the record before the sandbox starts and each stage is
    written as it happens, so the wait — minutes, for Android — is not silent
    for whoever is watching.
    """
    state = app.state
    detonator = getattr(state, "detonator", None)
    if detonator is None:
        return

    platform, engine = detonator.engine_for(result)
    if platform is None:
        return

    with state.database.session() as session:
        sample = session.get(Sample, sample_id)
        if sample is None:
            return
        sample.status = "detonating"
        run_id = start_run(session, sample_id, platform, engine)
        session.commit()

    def note(message: str) -> None:
        """Persist one progress line immediately, in its own transaction.

        Its own session because this is called from inside the sandbox while the
        long-running work is in flight; holding a session open for the whole
        detonation would keep a connection pinned for minutes.
        """
        try:
            with state.database.session() as session:
                append_progress(session, run_id, message)
                session.commit()
        except Exception:  # noqa: BLE001 - progress must never break a run
            pass

    try:
        outcome = detonator.run(path, result, on_progress=note)
    except Exception as exc:  # noqa: BLE001 - a sandbox never fails the report
        outcome = DetonationResult.failed(
            platform=platform,
            engine=engine,
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            error=f"{type(exc).__name__}: {exc}",
        )

    with state.database.session() as session:
        sample = session.get(Sample, sample_id)
        if sample is None:
            return
        if outcome is not None:
            finish_run(session, run_id, outcome)
            if outcome.executed:
                _restate_verdict(state.settings, sample, result, outcome)
        sample.status = "complete"
        sample.completed_at = datetime.now(timezone.utc)
        session.commit()


def _restate_verdict(settings, sample: Sample, result, outcome) -> None:
    """Recompute the verdict now that there is evidence of what the file did.

    Observed exfiltration is the strongest thing this system can establish, so
    the assessment is redone from the same static findings plus the
    observations, rather than the dynamic section being bolted onto a verdict
    that was reached without it.
    """
    findings = result.findings
    findings.detonation = outcome
    findings.exfiltration = correlate(
        outcome.events,
        window_ms=settings.exfiltration_window_ms,
        timed=outcome.timed,
    )

    summary = summarize(findings)
    sample.verdict = summary.level
    sample.headline = summary.headline
    sample.narrative = summary.narrative
    sample.reasons = summary.reasons

    # The stored prose was written about a report that said the file had never
    # been run. It is now describing a different document, so it is dropped and
    # will be redrafted on the next export.
    sample.narrative_sections = None
    sample.narrative_model = None


def _persist(session, sample: Sample, result) -> None:
    sample.detected_type = result.detected_type
    sample.verdict = result.summary.level
    sample.headline = result.summary.headline
    sample.narrative = result.summary.narrative
    sample.reasons = result.summary.reasons
    sample.warnings = result.warnings

    for leaf in result.files:
        session.add(
            LeafFile(
                sample_id=sample.id,
                relative_name=leaf.relative_name,
                sha256=leaf.sha256,
                detected_type=leaf.detected_type,
                size=leaf.size,
                is_pe=leaf.pe is not None,
                machine=leaf.pe.machine if leaf.pe else None,
                likely_packed=bool(leaf.pe and leaf.pe.packing.likely_packed),
                packing_reasons=leaf.pe.packing.reasons if leaf.pe else [],
                imported_dlls=leaf.pe.imported_dlls if leaf.pe else [],
                sections=(
                    [
                        {
                            "name": section.name,
                            "entropy": round(section.entropy, 2),
                            "raw_size": section.raw_size,
                            "virtual_size": section.virtual_size,
                        }
                        for section in leaf.pe.sections
                    ]
                    if leaf.pe
                    else []
                ),
                notable_strings=leaf.notable_strings,
                **_android_columns(leaf.apk),
            )
        )
        for match in leaf.yara:
            session.add(
                YaraHit(
                    sample_id=sample.id,
                    rule=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta={k: str(v) for k, v in match.meta.items()},
                )
            )

    for finding in result.indicators:
        session.add(
            Ioc(
                sample_id=sample.id,
                type=finding.type,
                value=finding.value,
                threatfox=_provider_payload(finding.threatfox),
                abuseipdb=_provider_payload(finding.abuseipdb),
                urlscan=_provider_payload(finding.urlscan),
            )
        )

    for technique in result.techniques:
        session.add(
            AttackTechnique(
                sample_id=sample.id,
                technique_id=technique.technique_id,
                name=technique.name,
                plain_language=technique.plain_language,
                evidence=list(technique.evidence),
                basis=technique.basis,
            )
        )

    for provider in _unique_providers(result.provider_statuses):
        session.add(
            ProviderStatus(
                sample_id=sample.id,
                provider=provider.provider,
                status=provider.status,
                detail=provider.detail,
            )
        )


def _android_columns(apk) -> dict:
    """APK fields for a leaf, or the empty defaults for anything else."""
    if apk is None:
        return {"is_apk": False}
    return {
        "is_apk": True,
        "package": apk.package or None,
        "app_label": apk.app_label or None,
        "permissions": list(apk.permissions),
        "dangerous_permissions": list(apk.dangerous_permissions),
        "high_abuse_permissions": list(apk.high_abuse_permissions),
        "components": {
            "activities": apk.activities,
            "services": apk.services,
            "receivers": apk.receivers,
            "providers": apk.providers,
        },
        "certificates": [
            {
                "subject": certificate.subject,
                "issuer": certificate.issuer,
                "sha256": certificate.sha256,
                "self_signed": certificate.self_signed,
            }
            for certificate in apk.certificates
        ],
        "signals": [
            {
                "code": signal.code,
                "plain_language": signal.plain_language,
                "detail": signal.detail,
            }
            for signal in apk.signals
        ],
    }


def _unique_providers(statuses: list[ProviderResult]) -> list[ProviderResult]:
    seen: dict[str, ProviderResult] = {}
    for status in statuses:
        seen.setdefault(status.provider, status)
    return list(seen.values())


def _provider_payload(result: ProviderResult | None) -> dict | None:
    if result is None or result.status != "ok":
        return None
    return result.data


@router.get("")
def list_samples(request: Request):
    with request.app.state.database.session() as session:
        samples = session.query(Sample).order_by(Sample.id.desc()).all()
        return [
            {
                "id": sample.id,
                "sha256": sample.sha256,
                "filename": sample.filename,
                "size": sample.size,
                # What the file was found to be, so the interface can separate
                # Android work from Windows work without trusting its name.
                "detected_type": sample.detected_type,
                "status": sample.status,
                "verdict": sample.verdict,
                "headline": sample.headline,
                "created_at": sample.created_at.isoformat() if sample.created_at else None,
            }
            for sample in samples
        ]


@router.get("/{sample_id}")
def get_sample(request: Request, sample_id: int):
    state = request.app.state
    with state.database.session() as session:
        sample = _load(session, sample_id)
        report = _serialize(sample)
        # Whether this server could run this file if asked. The interface needs
        # it to decide whether to offer the button at all, rather than offering
        # one that fails on a server with no sandbox configured.
        report["can_detonate"] = _can_detonate(state.settings, sample)
        return report


def _can_detonate(settings, sample: Sample) -> bool:
    if sample.status != "complete":
        return False
    if any(run.status == "running" for run in sample.detonations):
        return False

    if any(leaf.is_apk for leaf in sample.files):
        # Android needs an SDK and a matching frida-server on this machine.
        return bool(settings.frida_server_path and settings.android_sdk_root)
    if any(leaf.is_pe for leaf in sample.files):
        # The Windows emulator is pure Python and needs nothing installed.
        return True
    return False


def _serialize(sample: Sample) -> dict:
    """The full report shape. Shared by the JSON endpoint and the Word export so
    the document can never describe a different report than the screen."""
    return {
        "id": sample.id,
        "sha256": sample.sha256,
        "md5": sample.md5,
        "sha1": sample.sha1,
        "filename": sample.filename,
        "size": sample.size,
        "detected_type": sample.detected_type,
        "status": sample.status,
        "verdict": sample.verdict,
        "headline": sample.headline,
        "narrative": sample.narrative,
        "reasons": sample.reasons or [],
        "warnings": sample.warnings or [],
        "error": sample.error,
        "created_at": sample.created_at.isoformat() if sample.created_at else None,
        "completed_at": (
            sample.completed_at.isoformat() if sample.completed_at else None
        ),
        "files": [
            {
                "relative_name": leaf.relative_name,
                "sha256": leaf.sha256,
                "detected_type": leaf.detected_type,
                "size": leaf.size,
                "is_pe": leaf.is_pe,
                "machine": leaf.machine,
                "likely_packed": leaf.likely_packed,
                "packing_reasons": leaf.packing_reasons or [],
                "imported_dlls": leaf.imported_dlls or [],
                "sections": leaf.sections or [],
                "is_apk": leaf.is_apk,
                "package": leaf.package,
                "app_label": leaf.app_label,
                "permissions": leaf.permissions or [],
                "dangerous_permissions": leaf.dangerous_permissions or [],
                "high_abuse_permissions": leaf.high_abuse_permissions or [],
                "components": leaf.components or {},
                "certificates": leaf.certificates or [],
                "signals": leaf.signals or [],
                "notable_strings": leaf.notable_strings or [],
            }
            for leaf in sample.files
        ],
        "indicators": [
            {
                "type": ioc.type,
                "value": ioc.value,
                "threatfox": ioc.threatfox,
                "abuseipdb": ioc.abuseipdb,
                "urlscan": ioc.urlscan,
            }
            for ioc in sample.indicators
        ],
        "yara": [
            {
                "rule": hit.rule,
                "namespace": hit.namespace,
                "tags": hit.tags or [],
                "meta": hit.meta or {},
            }
            for hit in sample.yara_hits
        ],
        "techniques": [
            {
                "technique_id": technique.technique_id,
                "name": technique.name,
                "plain_language": technique.plain_language,
                "evidence": technique.evidence or [],
                "basis": technique.basis,
            }
            for technique in sample.techniques
        ],
        "providers": [
            {
                "provider": provider.provider,
                "status": provider.status,
                "detail": provider.detail,
            }
            for provider in sample.providers
        ],
        "detonations": [_serialize_run(run) for run in sample.detonations],
    }


def _serialize_run(run) -> dict:
    """One sandbox run, with its timeline and what the timeline implies.

    The exfiltration pairing is derived here rather than stored, so there is one
    definition of it and no way for a saved finding to drift out of step with
    the events it was drawn from.
    """
    events = [
        BehaviorEvent(
            at=row.at,
            offset_ms=row.offset_ms,
            category=row.category,
            action=row.action,
            target=row.target,
            detail=row.detail,
            source=row.source,
            size_bytes=row.size_bytes,
            record_count=row.record_count,
        )
        for row in sorted(run.events, key=lambda row: (row.offset_ms, row.id))
    ]
    executed = run.status in {"complete", "timeout"}

    return {
        "platform": run.platform,
        "engine": run.engine,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "error": run.error,
        "timed": run.timed,
        "coverage": run.coverage,
        "artifacts": run.artifacts or {},
        # What the sandbox reported while it worked, so a long wait is visible.
        "progress": run.progress or [],
        "events": [
            {
                "at": event.at.isoformat() if event.at else None,
                "offset_ms": event.offset_ms,
                "category": event.category,
                "action": event.action,
                "target": event.target,
                "detail": event.detail,
                "source": event.source,
                "size_bytes": event.size_bytes,
                "record_count": event.record_count,
                # Stated on every event so nothing downstream can render an
                # observation in the same list as a static capability.
                "basis": DYNAMIC_BASIS,
            }
            for event in events
        ],
        # A failed run observed nothing, so it can imply nothing.
        "exfiltration": (
            [
                {
                    "what": finding.what,
                    "where": finding.where,
                    "when": finding.when.isoformat() if finding.when else None,
                    "gap_ms": finding.gap_ms,
                    "bytes_sent": finding.bytes_sent,
                    "confidence": finding.confidence,
                }
                for finding in correlate(events, timed=run.timed)
            ]
            if executed
            else []
        ),
    }


@router.get("/{sample_id}/export.csv")
def export_csv(request: Request, sample_id: int):
    with request.app.state.database.session() as session:
        report = _export_model(_load(session, sample_id))
    return PlainTextResponse(
        iocs_to_csv(report),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="iocs-{report.sha256[:12]}.csv"'
        },
    )


@router.get("/{sample_id}/export.stix")
def export_stix(request: Request, sample_id: int):
    with request.app.state.database.session() as session:
        report = _export_model(_load(session, sample_id))
    return JSONResponse(
        content=__import__("json").loads(iocs_to_stix(report)),
        headers={
            "Content-Disposition": f'attachment; filename="iocs-{report.sha256[:12]}.json"'
        },
    )


@router.get("/{sample_id}/export.docx")
def export_docx(request: Request, sample_id: int, refresh: bool = False):
    """The filed report, as a Word document.

    The narrative is drafted on first download rather than during analysis: it is
    the slowest step by far, and most samples are never exported. Once written it
    is stored, so re-downloading a report does not reword it — two copies of the
    same case file must not read differently.
    """
    state = request.app.state
    with state.database.session() as session:
        sample = _load(session, sample_id)
        if sample.status != "complete":
            raise HTTPException(
                status_code=409,
                detail="the analysis for this sample has not finished",
            )

        report = _serialize(sample)

        if sample.narrative_sections and not refresh:
            narrative = NarrativeResult(
                status="ok",
                sections=dict(sample.narrative_sections),
                model=sample.narrative_model or "",
            )
        else:
            narrative = state.narrator.write(report)
            if narrative.status == "ok":
                sample.narrative_sections = narrative.sections
                sample.narrative_model = narrative.model
                session.commit()

        document = report_to_docx(
            report, authority=state.settings.report_authority, narrative=narrative
        )

    return Response(
        content=document,
        media_type=(
            "application/vnd.openxmlformats-officedocument"
            ".wordprocessingml.document"
        ),
        headers={
            "Content-Disposition": (
                f'attachment; filename="report-{report["sha256"][:12]}.docx"'
            ),
            # Lets the interface report why a narrative is missing without
            # having to parse the document.
            "X-Narrative-Status": narrative.status,
        },
    )


def _load(session, sample_id: int) -> Sample:
    sample = session.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(status_code=404, detail="sample not found")
    return sample


def _export_model(sample: Sample) -> ReportExport:
    return ReportExport(
        sha256=sample.sha256,
        md5=sample.md5,
        sha1=sample.sha1,
        filename=sample.filename,
        verdict=sample.verdict or "unknown",
        analyzed_at=sample.completed_at,
        yara_rules=[hit.rule for hit in sample.yara_hits],
        indicators=[
            IndicatorFinding(
                type=ioc.type,
                value=ioc.value,
                threatfox=_rehydrate("threatfox", ioc.threatfox),
                abuseipdb=_rehydrate("abuseipdb", ioc.abuseipdb),
                urlscan=_rehydrate("urlscan", ioc.urlscan),
            )
            for ioc in sample.indicators
        ],
    )


def _rehydrate(provider: str, payload: dict | None) -> ProviderResult | None:
    if not payload:
        return None
    return ProviderResult(provider=provider, status="ok", data=payload)
