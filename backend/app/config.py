"""Runtime configuration, read from the environment / .env."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # Every key is optional. A missing key marks that provider "skipped" in the
    # report rather than failing the analysis.
    vt_api_key: str | None = None
    abusech_auth_key: str | None = None  # covers MalwareBazaar and ThreatFox
    abuseipdb_api_key: str | None = None
    urlscan_api_key: str | None = None

    # Air-gapped operation: no network calls at all, full local report still produced.
    offline_mode: bool = False

    database_url: str = "postgresql+psycopg2://malware:malware@db:5432/malware_analysis"
    sample_storage_dir: Path = BACKEND_ROOT / "storage" / "samples"
    yara_rules_dir: Path = BACKEND_ROOT / "yara_rules"

    # VirusTotal's public tier allows 4 requests/minute. Without a per-sample
    # budget one archive full of files would stall a report for many minutes.
    virustotal_calls_per_minute: int = 4
    max_hash_lookups_per_sample: int = 10
    max_indicator_lookups_per_sample: int = 25

    max_upload_bytes: int = 512 * 1024 * 1024

    # Dynamic analysis. Off by default: an Android detonation boots an emulator,
    # which takes minutes and several gigabytes of RAM, and an operator should
    # opt into that rather than discover it by uploading a file. The Windows
    # side needs nothing installed, but is gated by the same switch so that
    # "was this sample run?" has a single answer per deployment.
    dynamic_analysis_enabled: bool = False
    android_sdk_root: Path | None = None
    android_avd_home: Path | None = None
    android_avd: str = "triage"
    frida_server_path: Path | None = None
    # How long the app is left running under instrumentation after its screens
    # have been exercised.
    detonation_dwell_seconds: int = 45
    detonation_boot_timeout_seconds: int = 300
    # Fabricated messages placed on the phone before the app starts. A
    # factory-fresh emulator has an empty inbox, so a harvester reads nothing and
    # the timeline shows an app doing no harm.
    detonation_decoy_messages: int = 12
    detonation_artifacts_dir: Path = BACKEND_ROOT / "storage" / "detonations"
    # How long after data is read a transmission can still plausibly carry it.
    exfiltration_window_ms: int = 5_000

    # Narrative writing (Ollama). Optional: without a key the Word report is
    # still produced, using the deterministic narrative the analysers generate.
    ollama_api_key: str | None = None
    ollama_host: str = "https://ollama.com"
    ollama_model: str = "gemma4:31b-cloud"
    ollama_timeout_seconds: float = 180.0

    # Printed at the head of every exported report.
    report_authority: str = "SURAT CYBER POLICE INDIA"


@lru_cache
def get_settings() -> Settings:
    return Settings()
