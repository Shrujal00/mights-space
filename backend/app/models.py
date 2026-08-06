"""Database schema.

Deliberately uses portable column types (JSON rather than JSONB) so the same
models run on the Postgres deployment and on SQLite in the test suite.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    md5: Mapped[str] = mapped_column(String(32))
    sha1: Mapped[str] = mapped_column(String(40))
    filename: Mapped[str] = mapped_column(String(512))
    size: Mapped[int] = mapped_column(Integer)
    detected_type: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[str] = mapped_column(String(16), default="queued")
    verdict: Mapped[str | None] = mapped_column(String(16), nullable=True)
    headline: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Prose written by the narrative model, cached after the first Word export so
    # the same report is not redrafted (and reworded) on every download.
    narrative_sections: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    narrative_model: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    files: Mapped[list["LeafFile"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    indicators: Mapped[list["Ioc"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    yara_hits: Mapped[list["YaraHit"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    techniques: Mapped[list["AttackTechnique"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    providers: Mapped[list["ProviderStatus"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )
    detonations: Mapped[list["DetonationRun"]] = relationship(
        back_populates="sample", cascade="all, delete-orphan"
    )


class LeafFile(Base):
    __tablename__ = "leaf_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"))
    relative_name: Mapped[str] = mapped_column(String(1024))
    sha256: Mapped[str] = mapped_column(String(64))
    detected_type: Mapped[str] = mapped_column(Text, default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    is_pe: Mapped[bool] = mapped_column(Boolean, default=False)
    machine: Mapped[str | None] = mapped_column(String(16), nullable=True)
    likely_packed: Mapped[bool] = mapped_column(Boolean, default=False)
    packing_reasons: Mapped[list] = mapped_column(JSON, default=list)
    imported_dlls: Mapped[list] = mapped_column(JSON, default=list)
    sections: Mapped[list] = mapped_column(JSON, default=list)

    # Android. Populated only for APKs; PE samples leave these empty.
    is_apk: Mapped[bool] = mapped_column(Boolean, default=False)
    package: Mapped[str | None] = mapped_column(String(256), nullable=True)
    app_label: Mapped[str | None] = mapped_column(String(256), nullable=True)
    permissions: Mapped[list] = mapped_column(JSON, default=list)
    dangerous_permissions: Mapped[list] = mapped_column(JSON, default=list)
    high_abuse_permissions: Mapped[list] = mapped_column(JSON, default=list)
    components: Mapped[dict] = mapped_column(JSON, default=dict)
    certificates: Mapped[list] = mapped_column(JSON, default=list)
    signals: Mapped[list] = mapped_column(JSON, default=list)
    notable_strings: Mapped[list] = mapped_column(JSON, default=list)

    sample: Mapped[Sample] = relationship(back_populates="files")


class Ioc(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"))
    type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(Text)
    threatfox: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    abuseipdb: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    urlscan: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    sample: Mapped[Sample] = relationship(back_populates="indicators")


class YaraHit(Base):
    __tablename__ = "yara_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"))
    rule: Mapped[str] = mapped_column(String(256))
    namespace: Mapped[str] = mapped_column(String(512), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    sample: Mapped[Sample] = relationship(back_populates="yara_hits")


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"))
    technique_id: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(256))
    plain_language: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    basis: Mapped[str] = mapped_column(String(32), default="static-import")

    sample: Mapped[Sample] = relationship(back_populates="techniques")


class ProviderStatus(Base):
    __tablename__ = "provider_statuses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"))
    provider: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str] = mapped_column(Text, default="")

    sample: Mapped[Sample] = relationship(back_populates="providers")


class DetonationRun(Base):
    """One attempt to run a sample inside a sandbox.

    A sample may have several: the Windows emulator and the Android emulator are
    separate engines, and a failed attempt is kept rather than overwritten so
    the report can state that detonation was tried and why it did not produce
    observations.
    """

    __tablename__ = "detonation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("samples.id"))
    platform: Mapped[str] = mapped_column(String(16))  # android | windows
    engine: Mapped[str] = mapped_column(String(32))  # frida | speakeasy
    # queued | running | complete | failed | timeout
    status: Mapped[str] = mapped_column(String(16), default="queued")
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error: Mapped[str] = mapped_column(Text, default="")
    # Paths to whatever the run left on disk: pcap, mitmproxy flows, logcat.
    artifacts: Mapped[dict] = mapped_column(JSON, default=dict)
    # False when the engine reports only the order of events, not their timing —
    # true of the Windows instruction emulator. The report must not print gaps
    # between such events as if they had been measured.
    timed: Mapped[bool] = mapped_column(Boolean, default=True)
    # How much of the sample the engine managed to observe.
    coverage: Mapped[str] = mapped_column(Text, default="")
    # What the sandbox reported while it was working, as {at, message} entries.
    # A detonation takes minutes; without this the interface has nothing true to
    # show and would have to fake a progress bar.
    progress: Mapped[list] = mapped_column(JSON, default=list)

    sample: Mapped[Sample] = relationship(back_populates="detonations")
    events: Mapped[list["BehaviorEventRow"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class BehaviorEventRow(Base):
    """One observed action, stored. Mirrors `analysis.behavior.BehaviorEvent`."""

    __tablename__ = "behavior_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("detonation_runs.id"))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    offset_ms: Mapped[int] = mapped_column(Integer, default=0)
    category: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(Text)
    detail: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="")
    # Kept as a number rather than folded into `detail`: the exfiltration total
    # must come from the measurement, never from parsing a sentence.
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Rows a read returned. NULL means "not counted", which is not zero.
    record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    run: Mapped[DetonationRun] = relationship(back_populates="events")
