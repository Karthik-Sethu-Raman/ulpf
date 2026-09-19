# services/pipeline/tests/test_hashchain.py — merkle_root math (pure, no deps).
# Test bodies verbatim from the plan; the hashlib import sits at module level
# (the plan had it function-local in test_two_leaves_pair, which would leave
# test_odd_duplicates_last with no hashlib binding).
import hashlib

from pipeline.hashchain import merkle_root


def test_single_leaf():
    assert merkle_root(["aa"]) == "aa"  # single hash is its own root
def test_two_leaves_pair():
    expected = hashlib.sha256(bytes.fromhex("aa") + bytes.fromhex("bb")).hexdigest()
    assert merkle_root(["aa", "bb"]) == expected
def test_odd_duplicates_last():
    r3 = merkle_root(["aa", "bb", "cc"])
    h01 = hashlib.sha256(bytes.fromhex("aa") + bytes.fromhex("bb")).hexdigest()
    h22 = hashlib.sha256(bytes.fromhex("cc") + bytes.fromhex("cc")).hexdigest()
    assert r3 == hashlib.sha256(bytes.fromhex(h01) + bytes.fromhex(h22)).hexdigest()
def test_order_matters():
    assert merkle_root(["aa", "bb"]) != merkle_root(["bb", "aa"])
