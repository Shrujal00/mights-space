"""Windows PE static inspection.

The parsing logic is deliberately split from the heuristics: `shannon_entropy`
and `assess_packing` are pure functions that can be reasoned about and tested
without a binary, while `analyze_pe` is a thin adapter over pefile. Samples are
parsed, never executed.
"""

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import log2
from pathlib import Path

import pefile

HIGH_ENTROPY_THRESHOLD = 7.2
FEW_IMPORTS_THRESHOLD = 10

PACKER_SECTION_NAMES = frozenset(
    {
        "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".themida", ".vmp0",
        ".vmp1", ".vmp2", ".petite", ".nsp0", ".nsp1", ".mpress1", ".mpress2",
        "MEW", ".boom", ".enigma1", ".enigma2", ".packed", "PELOCKnt",
    }
)

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "arm",
    0x01C4: "armv7",
    0xAA64: "arm64",
    0x0200: "ia64",
}


@dataclass
class SectionInfo:
    name: str
    entropy: float
    raw_size: int
    virtual_size: int


@dataclass
class PackingAssessment:
    likely_packed: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class PeReport:
    machine: str
    compile_timestamp: datetime | None
    is_signed: bool
    sections: list[SectionInfo]
    imported_dlls: list[str]
    imported_functions: list[str]
    packing: PackingAssessment
    version_strings: list[str] = field(default_factory=list)


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte, 0.0 (uniform) to 8.0 (random)."""
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (count / length) * log2(count / length) for count in Counter(data).values()
    )


def assess_packing(
    sections: list[SectionInfo], import_count: int
) -> PackingAssessment:
    """Heuristic packer detection.

    A recognised packer section name is conclusive on its own. High entropy is
    not — compressed resources push plenty of legitimate binaries above the
    threshold — so it only counts alongside a suspiciously thin import table,
    which is the tell-tale sign of an unpacking stub.
    """
    reasons: list[str] = []

    packer_sections = [
        section.name
        for section in sections
        if section.name in PACKER_SECTION_NAMES
        or section.name.upper().startswith("UPX")
    ]
    if packer_sections:
        reasons.append(
            f"section names associated with packers: {', '.join(packer_sections)}"
        )

    high_entropy = [
        section.name
        for section in sections
        if section.entropy >= HIGH_ENTROPY_THRESHOLD
    ]
    if high_entropy:
        reasons.append(
            f"high-entropy sections suggesting compressed or encrypted code: "
            f"{', '.join(high_entropy)}"
        )

    few_imports = import_count < FEW_IMPORTS_THRESHOLD
    if few_imports:
        reasons.append(
            f"unusually small import table ({import_count} functions), typical of "
            "code that resolves its imports at run time"
        )

    likely_packed = bool(packer_sections) or (bool(high_entropy) and few_imports)
    return PackingAssessment(likely_packed=likely_packed, reasons=reasons)


def is_pe(path: Path) -> bool:
    try:
        pefile.PE(str(path), fast_load=True).close()
    except (pefile.PEFormatError, OSError):
        return False
    return True


def analyze_pe(path: Path) -> PeReport:
    binary = pefile.PE(str(path))
    try:
        sections = [
            SectionInfo(
                name=section.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                entropy=shannon_entropy(section.get_data()),
                raw_size=section.SizeOfRawData,
                virtual_size=section.Misc_VirtualSize,
            )
            for section in binary.sections
        ]

        dlls: list[str] = []
        functions: list[str] = []
        for entry in getattr(binary, "DIRECTORY_ENTRY_IMPORT", []):
            if entry.dll:
                dlls.append(entry.dll.decode("utf-8", errors="replace"))
            for imported in entry.imports:
                if imported.name:
                    functions.append(imported.name.decode("utf-8", errors="replace"))

        return PeReport(
            machine=MACHINE_NAMES.get(
                binary.FILE_HEADER.Machine, hex(binary.FILE_HEADER.Machine)
            ),
            compile_timestamp=_compile_timestamp(binary),
            is_signed=_has_signature(binary),
            sections=sections,
            imported_dlls=dlls,
            imported_functions=functions,
            packing=assess_packing(sections, len(functions)),
            version_strings=_version_strings(binary),
        )
    finally:
        binary.close()


def _version_strings(binary: pefile.PE) -> list[str]:
    """Values from the version resource, e.g. FileVersion "1.1.0.14".

    These are stored as bare strings with their key held separately, so by the
    time they reach the string extractor they are indistinguishable from an IPv4
    address. Reading them structurally lets the IOC extractor exclude them
    precisely instead of guessing.
    """
    binary.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )
    values: list[str] = []
    for file_info in getattr(binary, "FileInfo", []):
        for entry in file_info:
            for string_table in getattr(entry, "StringTable", []):
                for key, value in string_table.entries.items():
                    if b"version" in key.lower():
                        values.append(value.decode("utf-8", errors="replace").strip())
    return values


def _compile_timestamp(binary: pefile.PE) -> datetime | None:
    raw = binary.FILE_HEADER.TimeDateStamp
    if not raw:
        return None
    try:
        return datetime.fromtimestamp(raw, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None  # Packers routinely forge nonsense timestamps.


def _has_signature(binary: pefile.PE) -> bool:
    directories = getattr(binary.OPTIONAL_HEADER, "DATA_DIRECTORY", [])
    security = next(
        (d for d in directories if d.name == "IMAGE_DIRECTORY_ENTRY_SECURITY"), None
    )
    return bool(security and security.VirtualAddress and security.Size)
