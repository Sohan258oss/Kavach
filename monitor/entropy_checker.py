"""
entropy_checker.py — Shannon entropy analysis with 3-chunk sampling.

Reads 4 KB from start, middle, and end of each file instead of the full
contents.  Maintains accuracy while dramatically improving speed on
large files.
"""

import math
import os
from typing import Tuple

from config import (
    ENTROPY_SKIP_EXTENSIONS,
    ENTROPY_THRESHOLD,
    ENTROPY_SAMPLE_CHUNK_SIZE,
)


def calculate_entropy(filepath: str) -> float:
    """
    Calculate Shannon entropy using a 3-chunk sampling strategy.

    * Files ≤ 12 KB  → read entirely (3 × 4 KB threshold).
    * Files > 12 KB  → sample 4 KB from start, middle, and end.
    * Skipped formats (.exe, .zip, …) → 0.0 immediately.

    Returns:
        Entropy in bits (0.0–8.0), 0.0 for skipped/empty, -1.0 on error.
    """
    try:
        ext: str = os.path.splitext(filepath)[1].lower()
        if ext in ENTROPY_SKIP_EXTENSIONS:
            return 0.0

        file_size: int = os.path.getsize(filepath)
        if file_size == 0:
            return 0.0

        chunk: int = ENTROPY_SAMPLE_CHUNK_SIZE  # 4 KB

        with open(filepath, 'rb') as f:
            if file_size <= chunk * 3:
                # Small file — read entirely
                data: bytes = f.read()
            else:
                # ── 3-chunk sampling: start / middle / end ──
                start_chunk: bytes = f.read(chunk)

                mid_offset: int = (file_size // 2) - (chunk // 2)
                f.seek(mid_offset)
                mid_chunk: bytes = f.read(chunk)

                f.seek(file_size - chunk)
                end_chunk: bytes = f.read(chunk)

                data = start_chunk + mid_chunk + end_chunk

        if not data:
            return 0.0

        # ── Shannon entropy ──
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy: float = 0.0
        length: int = len(data)
        for count in freq.values():
            p: float = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    except (PermissionError, FileNotFoundError):
        return 0.0
    except Exception:
        return -1.0


def is_suspicious_entropy(
    filepath: str,
    threshold: float = ENTROPY_THRESHOLD,
) -> Tuple[bool, float]:
    """
    Check whether a file's entropy exceeds the suspicious threshold.

    Returns:
        (is_suspicious, entropy_value)
    """
    entropy: float = calculate_entropy(filepath)
    if entropy < 0:
        return False, 0.0
    return entropy > threshold, entropy