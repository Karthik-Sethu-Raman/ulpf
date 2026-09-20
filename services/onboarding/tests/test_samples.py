# services/onboarding/tests/test_samples.py — the deterministic prompt /
# held-out split (spec §6.2 anti-leakage guarantee).
#
# assign_roles consumes the (captured_at, id)-ordered row list load_samples
# produces and re-splits it from scratch: first prompt_size rows -> prompt,
# next held_out_size -> held_out, the rest -> unused.
from onboarding.samples import assign_roles


def _rows(n):
    # Already ordered by (captured_at, id) — the load_samples contract.
    return [{"id": i, "raw_text": f"line {i}"} for i in range(n)]


def test_twenty_rows_split_5_15_0():
    split = assign_roles(_rows(20))
    assert set(split) == {"prompt", "held_out", "unused"}
    assert [r["id"] for r in split["prompt"]] == list(range(5))
    assert [r["id"] for r in split["held_out"]] == list(range(5, 20))
    assert split["unused"] == []


def test_twenty_five_rows_split_5_15_5():
    split = assign_roles(_rows(25))
    assert [r["id"] for r in split["prompt"]] == list(range(5))
    assert [r["id"] for r in split["held_out"]] == list(range(5, 20))
    assert [r["id"] for r in split["unused"]] == list(range(20, 25))


def test_split_is_non_overlapping_by_id():
    split = assign_roles(_rows(23))
    flat = [r["id"] for role in ("prompt", "held_out", "unused") for r in split[role]]
    assert len(flat) == len(set(flat)) == 23  # leakage guarantee: no id in two roles
