"""
Forensic Hashing Engine for ForensiX.

Responsible for calculating cryptographic digests (MD5 and SHA-256) of evidence
files in binary read-only mode using streaming chunks without modifying the evidence.
"""

from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple, Union
import hashlib

# Default chunk size: 64 KB (65,536 bytes)
# Provides optimal streaming I/O throughput without loading entire files into memory.
DEFAULT_CHUNK_SIZE: int = 65536


class HashAlgorithms(str, Enum):
    """Cryptographic hash algorithms supported by ForensiX."""

    MD5 = "md5"
    SHA256 = "sha256"
    SHA512 = "sha512"


HashAlgorithm = HashAlgorithms

DEFAULT_ALGORITHMS: Tuple[str, ...] = (HashAlgorithms.MD5.value, HashAlgorithms.SHA256.value)


def compute_hashes(
    file_path: Union[str, Path],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    algorithms: Optional[Iterable[Union[HashAlgorithms, str]]] = None,
) -> Dict[str, str]:
    """
    Compute MD5, SHA-256, or SHA-512 cryptographic hashes for an evidence file.

    Follows forensic integrity principles:
    - Opens target strictly in binary read-only mode ('rb').
    - Reads the file streamingly in fixed chunks to handle any file size efficiently.
    - Computes all requested digests in a single I/O pass over the evidence data.
    - Never modifies the target file.

    Args:
        file_path: Path to the target evidence file (str or Path).
        chunk_size: Number of bytes to read per chunk (default: 65,536).
        algorithms: Optional iterable of algorithms to compute (e.g. HashAlgorithms.SHA512,
            'sha256', 'md5'). Defaults to ('md5', 'sha256') for backwards compatibility.

    Returns:
        Dict[str, str]: A dictionary containing hexadecimal hash digests.

    Raises:
        FileNotFoundError: If the evidence file does not exist.
        IsADirectoryError: If the provided path points to a directory.
        ValueError: If the path is not a regular file, chunk_size is invalid, or
            an unsupported algorithm is requested.
        PermissionError: If read permissions are denied on the target.
    """
    if isinstance(chunk_size, (list, tuple, set, HashAlgorithms)) or (isinstance(chunk_size, str) and not chunk_size.isdigit()):
        algorithms = chunk_size
        chunk_size = DEFAULT_CHUNK_SIZE

    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size}")

    target = Path(file_path).resolve()

    if not target.exists():
        raise FileNotFoundError(f"Evidence file does not exist: {target}")

    if target.is_dir():
        raise IsADirectoryError(f"Target path is a directory, not a regular file: {target}")

    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: {target}")

    if algorithms is None:
        algo_list = [HashAlgorithms.MD5.value, HashAlgorithms.SHA256.value]
    else:
        algo_list = []
        for algo in algorithms:
            algo_key = algo.value if isinstance(algo, HashAlgorithms) else str(algo).strip().lower()
            if algo_key not in (HashAlgorithms.MD5.value, HashAlgorithms.SHA256.value, HashAlgorithms.SHA512.value):
                raise ValueError(f"Unsupported hash algorithm '{algo_key}': supported are 'md5', 'sha256', 'sha512'")
            if algo_key not in algo_list:
                algo_list.append(algo_key)

    hashers: Dict[str, hashlib._Hash] = {}
    for algo_name in algo_list:
        if algo_name == HashAlgorithms.MD5.value:
            try:
                hashers[algo_name] = hashlib.md5(usedforsecurity=False)
            except TypeError:
                hashers[algo_name] = hashlib.md5()
        elif algo_name == HashAlgorithms.SHA256.value:
            hashers[algo_name] = hashlib.sha256()
        elif algo_name == HashAlgorithms.SHA512.value:
            hashers[algo_name] = hashlib.sha512()

    try:
        with target.open(mode="rb") as stream:
            while chunk := stream.read(chunk_size):
                for h in hashers.values():
                    h.update(chunk)
    except PermissionError as err:
        raise PermissionError(f"Permission denied: unable to read evidence file: {target}") from err
    except OSError as err:
        raise OSError(f"Failed to read evidence file '{target}': {err}") from err

    return {algo: h.hexdigest() for algo, h in hashers.items()}


compute_file_hashes = compute_hashes
