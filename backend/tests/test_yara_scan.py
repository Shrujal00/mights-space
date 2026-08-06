import pytest

from app.analysis.yara_scan import YaraScanner

MARKER_RULE = """
rule FindsMarker
{
    meta:
        description = "detects the test marker"
        author = "test suite"
    strings:
        $marker = "SUSPICIOUS_MARKER"
    condition:
        $marker
}
"""

TAGGED_RULE = """
rule TaggedRule : trojan stealer
{
    strings:
        $marker = "SUSPICIOUS_MARKER"
    condition:
        $marker
}
"""

# References a module that standard yara-python builds do not include, which is
# exactly how real community rulesets fail.
UNCOMPILABLE_RULE = """
import "cuckoo"

rule NeedsCuckoo
{
    condition:
        cuckoo.network.http_request(/evil/)
}
"""


@pytest.fixture
def rules_dir(tmp_path):
    directory = tmp_path / "rules"
    directory.mkdir()
    return directory


def test_matches_a_rule_against_bytes(rules_dir):
    (rules_dir / "marker.yar").write_text(MARKER_RULE)

    matches = YaraScanner(rules_dir).scan_bytes(b"padding SUSPICIOUS_MARKER padding")

    assert [m.rule for m in matches] == ["FindsMarker"]


def test_reports_no_matches_for_clean_data(rules_dir):
    (rules_dir / "marker.yar").write_text(MARKER_RULE)

    assert YaraScanner(rules_dir).scan_bytes(b"entirely ordinary content") == []


def test_matches_against_a_file_on_disk(rules_dir, tmp_path):
    (rules_dir / "marker.yar").write_text(MARKER_RULE)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00\x01SUSPICIOUS_MARKER\xff")

    matches = YaraScanner(rules_dir).scan_file(sample)

    assert [m.rule for m in matches] == ["FindsMarker"]


def test_exposes_rule_metadata(rules_dir):
    (rules_dir / "marker.yar").write_text(MARKER_RULE)

    (match,) = YaraScanner(rules_dir).scan_bytes(b"SUSPICIOUS_MARKER")

    assert match.meta["description"] == "detects the test marker"


def test_exposes_rule_tags(rules_dir):
    (rules_dir / "tagged.yar").write_text(TAGGED_RULE)

    (match,) = YaraScanner(rules_dir).scan_bytes(b"SUSPICIOUS_MARKER")

    assert sorted(match.tags) == ["stealer", "trojan"]


def test_one_broken_rule_file_does_not_disable_the_rest(rules_dir):
    # Community rulesets always contain a few files that will not compile here.
    # Losing the entire ruleset to one of them would silently gut detection.
    (rules_dir / "good.yar").write_text(MARKER_RULE)
    (rules_dir / "broken.yar").write_text(UNCOMPILABLE_RULE)

    scanner = YaraScanner(rules_dir)

    assert scanner.loaded_files == 1
    assert [name for name, _ in scanner.skipped_files] == ["broken.yar"]
    assert [m.rule for m in scanner.scan_bytes(b"SUSPICIOUS_MARKER")] == ["FindsMarker"]


def test_duplicate_rule_names_across_files_are_tolerated(rules_dir):
    # Large rulesets reuse rule identifiers across files; namespacing per file
    # keeps a collision from breaking the compile.
    (rules_dir / "first.yar").write_text(MARKER_RULE)
    (rules_dir / "second.yar").write_text(MARKER_RULE)

    scanner = YaraScanner(rules_dir)

    assert scanner.loaded_files == 2
    assert len(scanner.scan_bytes(b"SUSPICIOUS_MARKER")) == 2


def test_an_empty_ruleset_scans_without_error(rules_dir):
    scanner = YaraScanner(rules_dir)

    assert scanner.loaded_files == 0
    assert scanner.scan_bytes(b"SUSPICIOUS_MARKER") == []


EXTERNAL_VAR_RULE = """
rule UsesFilename
{
    condition:
        filename == "evil.exe"
}
"""


def test_compiles_rules_that_reference_standard_external_variables(rules_dir):
    # A large share of signature-base rules test filename/filepath/extension.
    # YARA rejects the whole file unless those are declared at compile time.
    (rules_dir / "ext.yar").write_text(EXTERNAL_VAR_RULE)

    scanner = YaraScanner(rules_dir)

    assert scanner.loaded_files == 1
    assert scanner.skipped_files == []


def test_supplies_the_real_filename_to_external_variable_rules(rules_dir, tmp_path):
    (rules_dir / "ext.yar").write_text(EXTERNAL_VAR_RULE)
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"anything at all")

    matches = YaraScanner(rules_dir).scan_file(sample)

    assert [m.rule for m in matches] == ["UsesFilename"]


def test_filename_can_be_overridden_for_files_extracted_from_an_archive(
    rules_dir, tmp_path
):
    # Extracted members are written under generated names, so the name inside
    # the archive has to be passed through or filename rules judge the wrong one.
    (rules_dir / "ext.yar").write_text(EXTERNAL_VAR_RULE)
    sample = tmp_path / "7_payload.bin"
    sample.write_bytes(b"anything at all")

    matches = YaraScanner(rules_dir).scan_file(sample, filename="evil.exe")

    assert [m.rule for m in matches] == ["UsesFilename"]


def test_finds_rules_in_nested_directories(rules_dir):
    nested = rules_dir / "malware" / "windows"
    nested.mkdir(parents=True)
    (nested / "marker.yara").write_text(MARKER_RULE)

    assert YaraScanner(rules_dir).loaded_files == 1
