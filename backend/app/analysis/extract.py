"""File-type detection and containment-aware archive extraction.

Input to this module is hostile by design, so extraction is bounded on every
axis an archive can attack: nesting depth, uncompressed size, member count, and
member path. Members are written to generated flat filenames using only the
basename, so even a traversal check that missed something could not place a file
outside the destination directory.

Nothing here executes a sample — archives are read and their contents written to
disk for later static inspection only.
"""

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import zipfile

import magic

from .apk_analysis import is_apk


@dataclass(frozen=True)
class ExtractionLimits:
    max_depth: int = 5
    max_files: int = 1000
    max_total_bytes: int = 500 * 1024 * 1024


@dataclass
class ExtractedFile:
    path: Path
    relative_name: str
    depth: int


@dataclass
class ExtractionResult:
    detected_type: str
    files: list[ExtractedFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class _Budget:
    total_bytes: int = 0
    counter: int = 0

    def next_id(self) -> int:
        self.counter += 1
        return self.counter


def detect_file_type(path: Path) -> str:
    """Human-readable libmagic description, e.g. 'Zip archive data, ...'."""
    return magic.from_file(str(path))


def is_traversal(name: str) -> bool:
    """True if an archive member name tries to escape the extraction root."""
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        return True
    if len(normalized) > 1 and normalized[1] == ":":  # Windows drive letter
        return True
    return ".." in PurePosixPath(normalized).parts


def extract_sample(
    path: Path,
    dest_dir: Path,
    limits: ExtractionLimits | None = None,
) -> ExtractionResult:
    """Expand `path` into its constituent files, bounded by `limits`."""
    limits = limits or ExtractionLimits()
    path, dest_dir = Path(path), Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    result = ExtractionResult(detected_type=detect_file_type(path))
    _walk(path, path.name, 0, dest_dir, limits, result, _Budget())
    return result


def _walk(
    source: Path,
    relative_name: str,
    depth: int,
    dest_dir: Path,
    limits: ExtractionLimits,
    result: ExtractionResult,
    budget: _Budget,
) -> None:
    if not zipfile.is_zipfile(source):
        _add_leaf(source, relative_name, depth, limits, result)
        return

    # An APK is a ZIP, but expanding one destroys the analysis: the manifest is
    # in binary XML and the code is a compressed DEX, so the members are
    # unreadable on their own and the app's permissions, components and strings
    # are all lost. It is passed through whole for the Android analyser instead.
    if is_apk(source):
        _add_leaf(source, relative_name, depth, limits, result)
        return

    if depth + 1 > limits.max_depth:
        result.warnings.append(
            f"maximum extraction depth ({limits.max_depth}) reached at "
            f"{relative_name!r}; nested contents were not expanded"
        )
        _add_leaf(source, relative_name, depth, limits, result)
        return

    try:
        _expand_archive(
            source, relative_name, depth, dest_dir, limits, result, budget
        )
    except (zipfile.BadZipFile, OSError) as exc:
        # Truncated or malformed archive: still report the file itself.
        result.warnings.append(f"could not read archive {relative_name!r}: {exc}")
        _add_leaf(source, relative_name, depth, limits, result)


def _expand_archive(
    source: Path,
    relative_name: str,
    depth: int,
    dest_dir: Path,
    limits: ExtractionLimits,
    result: ExtractionResult,
    budget: _Budget,
) -> None:
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue

            if len(result.files) >= limits.max_files:
                result.warnings.append(
                    f"file count limit ({limits.max_files}) reached; "
                    "remaining archive members were skipped"
                )
                return

            if is_traversal(info.filename):
                result.warnings.append(
                    f"rejected path traversal entry {info.filename!r} in "
                    f"{relative_name!r}"
                )
                continue

            # Checked before extracting: a zip bomb is small on disk and only
            # declares its true size in the header.
            if budget.total_bytes + info.file_size > limits.max_total_bytes:
                result.warnings.append(
                    f"skipped {info.filename!r}: declared uncompressed size would "
                    f"exceed the total size cap ({limits.max_total_bytes} bytes)"
                )
                continue

            member_name = (
                info.filename if depth == 0 else f"{relative_name}/{info.filename}"
            )
            # Basename only — the written path cannot escape dest_dir by construction.
            target = dest_dir / f"{budget.next_id()}_{PurePosixPath(info.filename).name}"
            with archive.open(info) as member, open(target, "wb") as out:
                written = 0
                while chunk := member.read(1024 * 1024):
                    written += len(chunk)
                    out.write(chunk)
            budget.total_bytes += written

            _walk(target, member_name, depth + 1, dest_dir, limits, result, budget)


def _add_leaf(
    source: Path,
    relative_name: str,
    depth: int,
    limits: ExtractionLimits,
    result: ExtractionResult,
) -> None:
    if len(result.files) >= limits.max_files:
        result.warnings.append(
            f"file count limit ({limits.max_files}) reached; "
            f"{relative_name!r} was skipped"
        )
        return
    result.files.append(ExtractedFile(source, relative_name, depth))
