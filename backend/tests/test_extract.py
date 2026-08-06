import zipfile

from app.analysis.extract import ExtractionLimits, extract_sample


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def test_non_archive_yields_the_file_itself(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not an archive")

    result = extract_sample(sample, tmp_path / "out")

    assert [f.relative_name for f in result.files] == ["sample.bin"]


def test_extracts_zip_members(tmp_path):
    archive = make_zip(tmp_path / "a.zip", {"one.txt": b"first", "two.txt": b"second"})

    result = extract_sample(archive, tmp_path / "out")

    assert sorted(f.relative_name for f in result.files) == ["one.txt", "two.txt"]


def test_recurses_into_nested_archives(tmp_path):
    inner = make_zip(tmp_path / "inner.zip", {"payload.exe": b"payload bytes"})
    outer = make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})

    result = extract_sample(outer, tmp_path / "out")

    assert any(f.relative_name.endswith("payload.exe") for f in result.files)


def test_rejects_path_traversal_entries(tmp_path):
    # zip-slip: an archive naming "../escaped.txt" must never write outside the
    # destination. The input here is hostile by design, so this is load-bearing.
    archive = tmp_path / "slip.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escaped.txt", b"escaped")

    result = extract_sample(archive, tmp_path / "out")

    assert not (tmp_path / "escaped.txt").exists()
    assert any("traversal" in warning.lower() for warning in result.warnings)


def test_rejects_absolute_path_entries(tmp_path):
    archive = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("/tmp/absolute_escape.txt", b"escaped")

    result = extract_sample(archive, tmp_path / "out")

    assert any("traversal" in warning.lower() for warning in result.warnings)


def test_stops_recursing_past_maximum_depth(tmp_path):
    inner = make_zip(tmp_path / "inner.zip", {"deep.txt": b"deep"})
    outer = make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})

    result = extract_sample(outer, tmp_path / "out", ExtractionLimits(max_depth=1))

    assert not any("deep.txt" in f.relative_name for f in result.files)
    assert any("depth" in warning.lower() for warning in result.warnings)


def test_refuses_entries_whose_declared_size_exceeds_the_cap(tmp_path):
    # A zip bomb is small on disk but enormous uncompressed, so the declared
    # uncompressed size must be checked *before* writing anything out.
    archive = make_zip(tmp_path / "bomb.zip", {"big.bin": b"A" * 100_000})

    result = extract_sample(
        archive, tmp_path / "out", ExtractionLimits(max_total_bytes=1_000)
    )

    assert not any("big.bin" in f.relative_name for f in result.files)
    assert any("size" in warning.lower() for warning in result.warnings)


def test_stops_when_file_count_exceeds_the_cap(tmp_path):
    archive = make_zip(tmp_path / "many.zip", {f"f{i}.txt": b"x" for i in range(10)})

    result = extract_sample(archive, tmp_path / "out", ExtractionLimits(max_files=3))

    assert len(result.files) <= 3
    assert any("limit" in warning.lower() for warning in result.warnings)


def test_treats_a_corrupt_archive_as_a_single_file_instead_of_failing(tmp_path):
    # Judges upload arbitrary files. A truncated or malformed archive must still
    # produce a report rather than aborting the analysis.
    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"PK\x03\x04 truncated garbage that is not a real zip")

    result = extract_sample(corrupt, tmp_path / "out")

    assert [f.relative_name for f in result.files] == ["corrupt.zip"]


def test_records_the_detected_file_type(tmp_path):
    archive = make_zip(tmp_path / "typed.zip", {"inside.txt": b"hello"})

    result = extract_sample(archive, tmp_path / "out")

    assert "zip" in result.detected_type.lower()
