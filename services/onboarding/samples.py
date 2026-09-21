# services/onboarding/samples.py — the deterministic prompt/held-out split
# (spec §6.2 anti-leakage fix).
#
# assign_roles re-splits the (captured_at, id)-ordered sample set from scratch
# on every run (controller ruling): first prompt_size rows -> prompt, next
# held_out_size -> held_out, the rest -> unused. Pure + deterministic, so a
# re-run before any new samples arrive reproduces the same split and
# store.mark_roles persists it idempotently (scoped by id lists). The split
# itself never leaks: a row id lands in exactly one role.
PROMPT_SIZE = 5
HELD_OUT_SIZE = 15


def assign_roles(rows: list[dict], prompt_size: int = PROMPT_SIZE,
                 held_out_size: int = HELD_OUT_SIZE) -> dict[str, list[dict]]:
    """Split (captured_at, id)-ordered sample rows into the three roles.

    The optional size kwargs default to the Config defaults; app.py passes the
    configured values through, tests and other callers can use the bare
    `assign_roles(rows)` form.
    """
    return {
        "prompt": rows[:prompt_size],
        "held_out": rows[prompt_size:prompt_size + held_out_size],
        "unused": rows[prompt_size + held_out_size:],
    }
