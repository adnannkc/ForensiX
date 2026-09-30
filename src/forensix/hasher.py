"""
Forensic Hashing Engine for ForensiX.

Responsible for calculating cryptographic digests (MD5 and SHA-256) of evidence
files in binary read-only mode using streaming chunks without modifying the evidence.
"""

from pathlib import Path
from typing import Dict, Union
import hashlib

# Default chunk size: 64 KB (65,536 bytes)
# Provides optimal streaming I/O throughput without loading entire files into memory.
DEFAULT_CHUNK_SIZE: int = 65536


def compute_hashes(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Dict[str, str]:
    """
    Compute MD5 and SHA-256 cryptographic hashes for an evidence file.

    Follows forensic integrity principles:
    - Opens target strictly in binary read-only mode ('rb').
    - Reads the file streamingly in fixed chunks to handle any file size efficiently.
    - Computes both digests in a single I/O pass over the evidence data.
    - Never modifies the target file.

    Args:
        file_path: Path to the target evidence file (str or Path).
        chunk_size: Number of bytes to read per chunk (default: 65,536).

    Returns:
        Dict[str, str]: A dictionary containing hexadecimal hash digests:
            {
                "md5": "<lowercase hex string>",
                "sha256": "<lowercase hex string>"
            }

    Raises:
        FileNotFoundError: If the evidence file does not exist.
        IsADirectoryError: If the provided path points to a directory.
        ValueError: If the path is not a regular file or chunk_size is invalid.
        PermissionError: If read permissions are denied on the target.
    """
    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size}")

    target = Path(file_path).resolve()

    if not target.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {target}")

    if target.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a regular file: {target}")

    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: {target}")

    # Use usedforsecurity=False where supported to allow MD5 in restricted/FIPS environments
    try:
        md5_hasher = hashlib.md5(usedforsecurity=False)
    except TypeError:
        md5_hasher = hashlib.md5()

    sha256_hasher = hashlib.sha256()

    try:
        with target.open(mode="rb") as stream:
            while chunk := stream.read(chunk_size):
                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)
    except PermissionError as err:
        raise PermissionError(f"Permission denied: unable to read evidence file: {target}") from err
    except OSError as err:
        raise OSError(f"Failed to read evidence file '{target}': {err}") from err

    return {
        "md5": md5_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest(),
    }
