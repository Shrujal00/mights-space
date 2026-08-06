"""File hashing. Samples are read, never executed."""

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024

ALGORITHMS = ("md5", "sha1", "sha256")


def hash_bytes(data: bytes) -> dict[str, str]:
    return {name: hashlib.new(name, data).hexdigest() for name in ALGORITHMS}


def hash_file(path: Path) -> dict[str, str]:
    """Hash a file in chunks — samples can be hundreds of megabytes."""
    digests = {name: hashlib.new(name) for name in ALGORITHMS}
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}
