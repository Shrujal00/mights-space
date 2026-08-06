"""YARA signature matching against a vendored community ruleset.

Real rulesets are messy: some files import modules a standard yara-python build
does not ship (`cuckoo`, `magic`), and rule identifiers are reused across files.
Both would abort a naive single compile and silently leave the tool with no
detection at all, so each file is validated on its own and loaded into its own
namespace. Files that cannot compile are skipped and reported rather than
bringing down the ruleset.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yara

RULE_SUFFIXES = (".yar", ".yara")

# Rules routinely test the name and location of the file being scanned. YARA
# rejects any file referencing an undeclared identifier, so these must be
# declared at compile time even when the value is unknown — without them, every
# rule file that mentions `filename` or `filepath` is lost.
EXTERNAL_VARIABLES: dict[str, str] = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]


class YaraScanner:
    """Compiles a rules directory once, then scans many samples against it."""

    def __init__(self, rules_dir: Path):
        self.rules_dir = Path(rules_dir)
        self.skipped_files: list[tuple[str, str]] = []

        sources: dict[str, str] = {}
        for path in self._rule_files():
            namespace = str(path.relative_to(self.rules_dir))
            try:
                # Validate in isolation so one bad file cannot poison the batch.
                yara.compile(filepath=str(path), externals=EXTERNAL_VARIABLES)
            except (yara.Error, UnicodeDecodeError) as exc:
                self.skipped_files.append((namespace, str(exc)))
                continue
            sources[namespace] = path.read_text(encoding="utf-8", errors="replace")

        self.loaded_files = len(sources)
        self._rules = (
            yara.compile(sources=sources, externals=EXTERNAL_VARIABLES)
            if sources
            else None
        )

    def _rule_files(self) -> list[Path]:
        return sorted(
            path
            for path in self.rules_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in RULE_SUFFIXES
        )

    def scan_bytes(self, data: bytes) -> list[YaraMatch]:
        if self._rules is None:
            return []
        return self._convert(self._rules.match(data=data))

    def scan_file(self, path: Path, filename: str | None = None) -> list[YaraMatch]:
        """Match a sample on disk. The file is read only, never executed.

        `filename` overrides the name shown to filename-based rules, so a file
        pulled out of an archive is judged by its name inside that archive
        rather than the generated name it was written under.
        """
        if self._rules is None:
            return []
        path = Path(path)
        display_name = filename or path.name
        externals = dict(EXTERNAL_VARIABLES)
        externals.update(
            filename=display_name,
            filepath=str(path),
            extension=Path(display_name).suffix,
        )
        return self._convert(
            self._rules.match(filepath=str(path), externals=externals)
        )

    @staticmethod
    def _convert(matches: list[Any]) -> list[YaraMatch]:
        return [
            YaraMatch(
                rule=match.rule,
                namespace=match.namespace,
                tags=tuple(match.tags),
                meta=dict(match.meta),
            )
            for match in matches
        ]
