"""Merkle root over batch content hashes — the raw_batches chain math (spec §4).

Pure functions, no dependencies: hex sha256 strings in, hex sha256 string out.
Each batch stores the merkle root of its ordered content_hash list in
raw_batches.row_hashes + merkle_root, and prev_hash links the previous batch's
merkle_root (GENESIS_PREV_HASH = 64 zeros for each partition's first batch).
The same function independently re-verifies every stored root in Task 12's
smoke (recompute merkle_root(row_hashes) and compare), so this stays
dependency-free and dead simple on purpose.
"""

from __future__ import annotations

import hashlib

# prev_hash of the first raw_batches row on each partition (spec §4).
GENESIS_PREV_HASH = "0" * 64


def merkle_root(content_hashes: list[str]) -> str:
    """Merkle root of ordered hex sha256 leaves.

    Pairwise sha256 of concatenated raw bytes; an odd level duplicates its last
    hash (Bitcoin-style). A single leaf is its own root. Empty input is a
    programmer error — a batch always carries at least one row — so it raises.
    """
    if not content_hashes:
        raise ValueError("merkle_root of an empty batch")
    level = list(content_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            hashlib.sha256(bytes.fromhex(level[i]) + bytes.fromhex(level[i + 1])).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]
