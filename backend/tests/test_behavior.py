from datetime import datetime, timedelta, timezone

import pytest

from app.analysis.behavior import BehaviorEvent, DetonationResult
from app.db import Database
from app.detonation import record_run, reconcile_interrupted_runs
from app.models import BehaviorEventRow, DetonationRun, Sample


@pytest.fixture
def database(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'behavior.db'}")
    db.create_all()
    yield db
    db.dispose()


@pytest.fixture
def sample_id(database):
    with database.session() as session:
        sample = Sample(
            sha256="a" * 64, md5="b" * 32, sha1="c" * 40, filename="x.apk", size=10
        )
        session.add(sample)
        session.commit()
        return sample.id


START = datetime(2026, 8, 6, 14, 3, 22, tzinfo=timezone.utc)


class TestBehaviorEvent:
    def test_offset_is_measured_from_the_start_of_the_detonation(self):
        event = BehaviorEvent.since(
            START,
            START + timedelta(seconds=3, milliseconds=500),
            category="network",
            action="sent",
            target="185.244.25.14:443",
            detail="34 KB",
            source="frida",
        )

        assert event.offset_ms == 3500

    def test_an_event_before_the_start_clamps_to_zero(self):
        event = BehaviorEvent.since(
            START,
            START - timedelta(seconds=1),
            category="process",
            action="started",
            target="com.example",
        )

        assert event.offset_ms == 0

    def test_events_are_frozen_so_a_report_cannot_be_edited_after_the_fact(self):
        event = BehaviorEvent.since(
            START, START, category="process", action="started", target="com.example"
        )

        with pytest.raises(AttributeError):
            event.target = "something else"  # type: ignore[misc]


class TestDetonationResult:
    def test_a_failed_detonation_carries_the_reason_and_no_events(self):
        result = DetonationResult.failed(
            platform="android",
            engine="frida",
            started_at=START,
            error="emulator did not boot",
        )

        assert result.status == "failed"
        assert result.error == "emulator did not boot"
        assert result.events == []

    def test_a_failed_detonation_is_not_treated_as_having_run_the_sample(self):
        result = DetonationResult.failed(
            platform="android", engine="frida", started_at=START, error="boom"
        )

        assert result.executed is False

    def test_a_complete_detonation_is_treated_as_having_run_the_sample(self):
        result = DetonationResult(
            platform="android",
            engine="frida",
            status="complete",
            started_at=START,
            finished_at=START + timedelta(seconds=60),
            events=[],
        )

        assert result.executed is True

    def test_a_timeout_still_counts_as_having_run_the_sample(self):
        """The sample executed; only the observation window ended early. The
        report must not claim the file was never run."""
        result = DetonationResult(
            platform="android",
            engine="frida",
            status="timeout",
            started_at=START,
            finished_at=START + timedelta(seconds=120),
            events=[],
        )

        assert result.executed is True


class TestPersistence:
    def test_a_recorded_run_reads_back_with_its_events(self, database, sample_id):
        result = DetonationResult(
            platform="android",
            engine="frida",
            status="complete",
            started_at=START,
            finished_at=START + timedelta(seconds=45),
            events=[
                BehaviorEvent.since(
                    START,
                    START,
                    category="data-access",
                    action="read",
                    target="SMS inbox",
                    detail="247 records",
                    source="frida",
                ),
                BehaviorEvent.since(
                    START,
                    START + timedelta(seconds=3),
                    category="network",
                    action="sent",
                    target="185.244.25.14:443",
                    detail="34 KB",
                    source="frida",
                ),
            ],
        )

        with database.session() as session:
            record_run(session, sample_id, result)
            session.commit()

        with database.session() as session:
            run = session.query(DetonationRun).one()
            events = (
                session.query(BehaviorEventRow)
                .filter(BehaviorEventRow.run_id == run.id)
                .order_by(BehaviorEventRow.offset_ms)
                .all()
            )

        assert run.platform == "android"
        assert run.engine == "frida"
        assert run.status == "complete"
        assert [event.target for event in events] == [
            "SMS inbox",
            "185.244.25.14:443",
        ]
        assert [event.offset_ms for event in events] == [0, 3000]
        assert events[0].detail == "247 records"

    def test_a_run_remembers_that_its_engine_had_no_clock(self, database, sample_id):
        """Whether the timeline may show measured gaps is a property of the run,
        and has to survive the trip to the database with it."""
        result = DetonationResult(
            platform="windows",
            engine="speakeasy",
            status="complete",
            started_at=START,
            finished_at=START,
            timed=False,
            coverage="Emulation traced 410 Windows API call(s).",
        )

        with database.session() as session:
            record_run(session, sample_id, result)
            session.commit()

        with database.session() as session:
            run = session.query(DetonationRun).one()

        assert run.timed is False
        assert "410" in run.coverage

    def test_a_failed_run_is_still_recorded_so_the_report_can_say_why(
        self, database, sample_id
    ):
        result = DetonationResult.failed(
            platform="windows",
            engine="speakeasy",
            started_at=START,
            error="emulation stopped at unsupported API",
        )

        with database.session() as session:
            record_run(session, sample_id, result)
            session.commit()

        with database.session() as session:
            run = session.query(DetonationRun).one()

        assert run.status == "failed"
        assert "unsupported API" in run.error


class TestReconciliation:
    def test_a_run_interrupted_by_a_restart_is_marked_failed(self, database, sample_id):
        with database.session() as session:
            session.add(
                DetonationRun(
                    sample_id=sample_id,
                    platform="android",
                    engine="frida",
                    status="running",
                    started_at=START,
                )
            )
            session.commit()

        with database.session() as session:
            reconcile_interrupted_runs(session)
            session.commit()

        with database.session() as session:
            run = session.query(DetonationRun).one()

        assert run.status == "failed"
        assert "restart" in run.error.lower()

    def test_a_sample_left_detonating_is_returned_to_a_reportable_state(
        self, database, sample_id
    ):
        """A crash mid-detonation must not leave the sample permanently showing a
        spinner. Its static report is already complete and still stands."""
        with database.session() as session:
            session.get(Sample, sample_id).status = "detonating"
            session.add(
                DetonationRun(
                    sample_id=sample_id,
                    platform="android",
                    engine="frida",
                    status="running",
                    started_at=START,
                )
            )
            session.commit()

        with database.session() as session:
            reconcile_interrupted_runs(session)
            session.commit()

        with database.session() as session:
            assert session.get(Sample, sample_id).status == "complete"

    def test_finished_runs_are_left_alone(self, database, sample_id):
        with database.session() as session:
            session.add(
                DetonationRun(
                    sample_id=sample_id,
                    platform="windows",
                    engine="speakeasy",
                    status="complete",
                    started_at=START,
                    finished_at=START,
                )
            )
            session.commit()

        with database.session() as session:
            reconcile_interrupted_runs(session)
            session.commit()

        with database.session() as session:
            run = session.query(DetonationRun).one()

        assert run.status == "complete"
        assert not run.error

    def test_starting_the_service_closes_runs_left_behind_by_the_last_one(
        self, tmp_path
    ):
        from app.config import Settings
        from app.main import create_app

        db_path = tmp_path / "startup.db"
        rules = tmp_path / "rules"
        rules.mkdir()

        database = Database(f"sqlite:///{db_path}")
        database.create_all()
        with database.session() as session:
            sample = Sample(
                sha256="d" * 64, md5="e" * 32, sha1="f" * 40, filename="y.apk", size=1
            )
            session.add(sample)
            session.flush()
            session.add(
                DetonationRun(
                    sample_id=sample.id,
                    platform="android",
                    engine="frida",
                    status="running",
                    started_at=START,
                )
            )
            session.commit()
        database.dispose()

        create_app(
            Settings(
                database_url=f"sqlite:///{db_path}",
                sample_storage_dir=tmp_path / "samples",
                yara_rules_dir=rules,
                offline_mode=True,
            )
        )

        reopened = Database(f"sqlite:///{db_path}")
        with reopened.session() as session:
            assert session.query(DetonationRun).one().status == "failed"
        reopened.dispose()

    def test_reconciliation_reports_how_many_runs_it_closed(self, database, sample_id):
        with database.session() as session:
            for _ in range(2):
                session.add(
                    DetonationRun(
                        sample_id=sample_id,
                        platform="android",
                        engine="frida",
                        status="running",
                        started_at=START,
                    )
                )
            session.commit()

        with database.session() as session:
            closed = reconcile_interrupted_runs(session)
            session.commit()

        assert closed == 2
