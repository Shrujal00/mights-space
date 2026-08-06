"""FastAPI application factory."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .analysis.enrichment import Enricher
from .analysis.narrative import NarrativeWriter
from .analysis.yara_scan import YaraScanner
from .api.samples import router as samples_router
from .config import Settings, get_settings
from .db import Database
from .detonation import reconcile_interrupted_runs
from .sandbox.runner import Detonator


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    database = Database(settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        database.dispose()

    app = FastAPI(
        title="Static Malware Triage",
        description=(
            "Static analysis of suspicious files for investigators. Samples are "
            "read and inspected — never executed."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    database.create_all()

    # A sandbox run cannot survive the process that started it. Anything still
    # marked running belongs to a previous life of this service and would
    # otherwise sit in the interface as a spinner that never resolves.
    with database.session() as session:
        reconcile_interrupted_runs(session)
        session.commit()

    Path(settings.sample_storage_dir).mkdir(parents=True, exist_ok=True)

    app.state.settings = settings
    app.state.database = database
    # Compiling the ruleset takes a moment, so it happens once here rather than
    # per upload.
    app.state.scanner = YaraScanner(settings.yara_rules_dir)
    app.state.enricher = Enricher(settings=settings)
    # One seam for all of dynamic analysis: off unless configured, and the only
    # thing a test has to replace to exercise the path without an emulator.
    app.state.detonator = Detonator(settings)
    app.state.narrator = NarrativeWriter(
        api_key=settings.ollama_api_key,
        host=settings.ollama_host,
        model=settings.ollama_model,
        timeout=settings.ollama_timeout_seconds,
        offline=settings.offline_mode,
    )

    app.include_router(samples_router)

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "offline_mode": settings.offline_mode,
            "yara_rules_loaded": app.state.scanner.loaded_files,
            "yara_rules_skipped": len(app.state.scanner.skipped_files),
        }

    return app


# No module-level app instance: constructing one on import would open a database
# connection as a side effect of merely importing this module. Served with
# `uvicorn app.main:create_app --factory`.
