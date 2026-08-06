"""Delete every stored case: database rows and the sample files on disk.

Two things have to happen together. Clearing the database alone leaves the
uploaded samples sitting in the storage directory — orphaned malware with nothing
recording what it is. Deleting the files alone leaves reports referring to
evidence that no longer exists.

The schema is left in place; only the contents are removed, so the service can
keep running and accept new uploads immediately afterwards.

Run with --yes to actually delete. Without it, this only reports what would go.
"""

import argparse
import shutil
import sys
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from app.config import get_settings
from app.db import Database
from app.models import (
    AttackTechnique,
    BehaviorEventRow,
    DetonationRun,
    Ioc,
    LeafFile,
    ProviderStatus,
    Sample,
    YaraHit,
)

# Children first. The foreign keys carry no ON DELETE CASCADE — the ORM handles
# that at the object level — so the database will reject deleting a sample while
# rows still point at it.
#
# Behaviour events hang off a detonation run rather than off the sample, so they
# have to go before it, and it before the sample: two levels, not one.
CHILD_MODELS = (
    BehaviorEventRow,
    DetonationRun,
    LeafFile,
    Ioc,
    YaraHit,
    AttackTechnique,
    ProviderStatus,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--yes", action="store_true", help="actually delete (default: report only)"
    )
    parser.add_argument(
        "--keep-files",
        action="store_true",
        help="clear the database but leave stored samples on disk",
    )
    args = parser.parse_args()

    settings = get_settings()
    database = Database(settings.database_url)
    storage = Path(settings.sample_storage_dir)

    try:
        counts = _counts(database)
    except OperationalError as exc:
        return _unreachable(settings.database_url, exc)

    stored = _stored_files(storage)

    print(f"database : {_redact(settings.database_url)}")
    print(f"storage  : {storage}")
    print()
    for name, count in counts.items():
        print(f"  {name:20} {count:>7}")
    print(f"  {'stored sample files':20} {len(stored):>7}")

    if not args.yes:
        print("\nNothing deleted. Re-run with --yes to remove all of the above.")
        return 0

    if counts["samples"] == 0 and not stored:
        print("\nAlready empty.")
        return 0

    removed_rows = _clear_database(database)
    removed_files = 0 if args.keep_files else _clear_storage(storage)

    print(f"\nDeleted {removed_rows} row(s) and {removed_files} file(s).")
    if args.keep_files:
        print("Sample files were left in place (--keep-files).")
    database.dispose()
    return 0


def _unreachable(url: str, exc: OperationalError) -> int:
    """Explain a failed connection instead of printing a connection-pool trace.

    The usual cause is running this on the host while `.env` still points at the
    Compose service name, which only resolves inside Docker.
    """
    print(f"Can't reach the database at {_redact(url)}", file=sys.stderr)
    host = url.rpartition("@")[2].split("/")[0].split(":")[0]
    if host and "." not in host and host not in ("localhost", ""):
        print(
            f"\nThe hostname {host!r} only resolves inside Docker. Either start "
            "the stack with ./start.sh and re-run, or set DATABASE_URL to a "
            "database reachable from here.",
            file=sys.stderr,
        )
    else:
        print(f"\n{str(exc.orig).strip()}", file=sys.stderr)
    return 1


def _counts(database: Database) -> dict[str, int]:
    names = {
        Sample: "samples",
        LeafFile: "files",
        Ioc: "indicators",
        YaraHit: "signature hits",
        AttackTechnique: "techniques",
        ProviderStatus: "provider results",
        DetonationRun: "sandbox runs",
        BehaviorEventRow: "observed events",
    }
    with database.session() as session:
        return {
            label: session.execute(select(func.count()).select_from(model)).scalar_one()
            for model, label in names.items()
        }


def _clear_database(database: Database) -> int:
    removed = 0
    with database.session() as session:
        for model in CHILD_MODELS:
            removed += session.query(model).delete(synchronize_session=False)
        removed += session.query(Sample).delete(synchronize_session=False)
        session.commit()
    return removed


def _stored_files(storage: Path) -> list[Path]:
    if not storage.is_dir():
        return []
    # Samples are stored under their SHA-256; .gitkeep is repository furniture.
    return [
        entry
        for entry in storage.iterdir()
        if entry.name != ".gitkeep" and not entry.name.startswith(".")
    ]


def _clear_storage(storage: Path) -> int:
    removed = 0
    for entry in _stored_files(storage):
        try:
            if entry.is_dir():
                # Extraction working directories, named work-<sample id>.
                shutil.rmtree(entry)
            else:
                entry.unlink()
            removed += 1
        except OSError as exc:
            print(f"  could not remove {entry.name}: {exc}", file=sys.stderr)
    return removed


def _redact(url: str) -> str:
    """Hide the password in a connection string before printing it."""
    if "://" not in url or "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    credentials, _, host = rest.rpartition("@")
    user = credentials.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"


if __name__ == "__main__":
    raise SystemExit(main())
