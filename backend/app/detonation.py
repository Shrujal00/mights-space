"""Storing detonation runs, and cleaning up after ones that never finished.

Kept apart from `analysis.behavior` so that module stays pure data and can be
exercised without a database, matching how the static analysers are split from
their I/O.
"""

from datetime import datetime, timezone

from .analysis.behavior import BehaviorEvent, DetonationResult
from .models import BehaviorEventRow, DetonationRun, Sample

INTERRUPTED_ERROR = "The sandbox run was interrupted by a restart of the service."


def start_run(session, sample_id: int, platform: str, engine: str) -> int:
    """Open a run before the sandbox starts, and return its id.

    The row exists for the whole time the sandbox is working, rather than being
    written once it finishes. That is what lets the interface show real progress
    during the wait, and it is also what makes `reconcile_interrupted_runs`
    meaningful — a run only looks abandoned if it was on the record while it was
    in flight.
    """
    run = DetonationRun(
        sample_id=sample_id,
        platform=platform,
        engine=engine,
        status="running",
        started_at=datetime.now(timezone.utc),
        progress=[],
    )
    session.add(run)
    session.flush()
    return run.id


def append_progress(session, run_id: int, message: str) -> None:
    """Record one line of what the sandbox is doing, as it happens."""
    run = session.get(DetonationRun, run_id)
    if run is None:
        return
    # Reassigned rather than appended in place: SQLAlchemy does not see a
    # mutation inside a JSON list, so an in-place append would never be saved.
    run.progress = list(run.progress or []) + [
        {"at": datetime.now(timezone.utc).isoformat(), "message": message}
    ]


def finish_run(session, run_id: int, result: DetonationResult) -> None:
    """Close an open run with what the sandbox found."""
    run = session.get(DetonationRun, run_id)
    if run is None:
        return

    run.platform = result.platform
    run.engine = result.engine
    run.status = result.status
    run.finished_at = result.finished_at or datetime.now(timezone.utc)
    run.error = result.error
    run.artifacts = dict(result.artifacts)
    run.timed = result.timed
    run.coverage = result.coverage

    for event in result.events:
        session.add(_event_row(run.id, event))


def record_run(session, sample_id: int, result: DetonationResult) -> DetonationRun:
    """Persist a finished run and its events. Failed runs are stored too, so a
    report can say detonation was attempted and explain what stopped it."""
    run = DetonationRun(
        sample_id=sample_id,
        platform=result.platform,
        engine=result.engine,
        status=result.status,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=result.error,
        artifacts=dict(result.artifacts),
        timed=result.timed,
        coverage=result.coverage,
    )
    session.add(run)
    session.flush()  # assigns run.id for the events below

    for event in result.events:
        session.add(_event_row(run.id, event))
    return run


def _event_row(run_id: int, event: BehaviorEvent) -> BehaviorEventRow:
    return BehaviorEventRow(
        run_id=run_id,
        at=event.at,
        offset_ms=event.offset_ms,
        category=event.category,
        action=event.action,
        target=event.target,
        detail=event.detail,
        source=event.source,
        size_bytes=event.size_bytes,
        record_count=event.record_count,
    )


def reconcile_interrupted_runs(session) -> int:
    """Close out runs that were in flight when the process last stopped.

    A sandbox run outlives no crash: if the service goes down mid-detonation
    there is nothing left to resume, and a run left `running` would show as a
    permanent spinner in the interface. The sample itself is returned to
    `complete`, because its static report finished long before detonation began
    and remains valid on its own.

    Returns the number of runs closed.
    """
    stranded = session.query(DetonationRun).filter(DetonationRun.status == "running").all()

    for run in stranded:
        run.status = "failed"
        run.error = INTERRUPTED_ERROR

    # `detonating` is only ever entered from `complete`, so going back to
    # `complete` restores exactly the state the sample was in. Marking it
    # `failed` instead would hide a static report that never stopped being valid.
    for sample in session.query(Sample).filter(Sample.status == "detonating").all():
        sample.status = "complete"

    return len(stranded)
