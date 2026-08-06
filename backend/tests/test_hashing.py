from app.analysis.hashing import hash_bytes, hash_file

# Well-known digests of b"hello".
HELLO_MD5 = "5d41402abc4b2a76b9719d911017c592"
HELLO_SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
HELLO_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_hash_bytes_returns_all_three_digests():
    assert hash_bytes(b"hello") == {
        "md5": HELLO_MD5,
        "sha1": HELLO_SHA1,
        "sha256": HELLO_SHA256,
    }


def test_hash_file_matches_hash_bytes(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")

    assert hash_file(sample) == hash_bytes(b"hello")


def test_hash_file_streams_files_larger_than_one_chunk(tmp_path):
    # Samples can be hundreds of MB; hashing must not read the whole file at once.
    payload = b"A" * (1024 * 1024 + 7)
    sample = tmp_path / "big.bin"
    sample.write_bytes(payload)

    assert hash_file(sample) == hash_bytes(payload)
