from pathlib import Path

import pytest

from app.analysis.pe_analysis import (
    SectionInfo,
    analyze_pe,
    assess_packing,
    is_pe,
    shannon_entropy,
)

FIXTURE = Path(__file__).parent / "fixtures" / "benign_pe32.exe"


class TestEntropy:
    def test_uniform_bytes_have_zero_entropy(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_evenly_distributed_bytes_approach_maximum_entropy(self):
        assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)

    def test_empty_data_has_zero_entropy(self):
        assert shannon_entropy(b"") == 0.0


class TestPackingHeuristics:
    def test_known_packer_section_names_are_conclusive(self):
        assessment = assess_packing(
            [SectionInfo("UPX0", 0.0, 0, 4096), SectionInfo("UPX1", 7.9, 4096, 4096)],
            import_count=50,
        )

        assert assessment.likely_packed
        assert any("UPX" in reason for reason in assessment.reasons)

    def test_high_entropy_combined_with_few_imports_indicates_packing(self):
        assessment = assess_packing(
            [SectionInfo(".text", 7.8, 4096, 4096)], import_count=3
        )

        assert assessment.likely_packed

    def test_high_entropy_alone_is_not_enough(self):
        # Compressed resources push entropy up in plenty of legitimate binaries.
        assessment = assess_packing(
            [SectionInfo(".rsrc", 7.6, 4096, 4096)], import_count=120
        )

        assert not assessment.likely_packed

    def test_ordinary_binary_is_not_flagged(self):
        assessment = assess_packing(
            [SectionInfo(".text", 6.1, 4096, 4096), SectionInfo(".rdata", 4.5, 1024, 1024)],
            import_count=80,
        )

        assert not assessment.likely_packed
        assert assessment.reasons == []


class TestRealPeFile:
    def test_detects_a_pe_file(self):
        assert is_pe(FIXTURE)

    def test_rejects_a_non_pe_file(self, tmp_path):
        plain = tmp_path / "notes.txt"
        plain.write_bytes(b"just some text, definitely not a PE")

        assert not is_pe(plain)

    def test_reads_architecture_and_sections(self):
        report = analyze_pe(FIXTURE)

        assert report.machine == "x86"
        assert ".text" in [section.name for section in report.sections]

    def test_reads_the_import_table(self):
        report = analyze_pe(FIXTURE)

        assert "KERNEL32.dll" in report.imported_dlls
        assert "ExitProcess" in report.imported_functions

    def test_computes_entropy_per_section(self):
        report = analyze_pe(FIXTURE)

        text = next(s for s in report.sections if s.name == ".text")
        assert 0.0 < text.entropy < 8.0

    def test_reads_the_values_from_the_version_resource(self):
        # These are stored as bare strings, with their key ("FileVersion") held
        # separately, so only the PE structure reveals that "1.1.0.14" is a
        # version rather than an address.
        report = analyze_pe(FIXTURE)

        assert "1.1.0.14" in report.version_strings

    def test_does_not_flag_the_benign_fixture_as_packed(self):
        report = analyze_pe(FIXTURE)

        assert not report.packing.likely_packed
