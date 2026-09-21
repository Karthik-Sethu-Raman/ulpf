# M2 SLM sanity numbers — onboarding candidate loop

> **FLAG (ruling 6): qwen3:4b stored ZERO rules on this host — held-out match
> is 0% on all three corpora, far below the 80% sanity threshold.** The table
> shows why this tier is not failing at JSON (valid_json 100%, compiles 100%):
> every response is well-formed and compiles, and every run still exhausts the
> 3-attempt ladder at "0.0 confidence. It failed to match the samples." The
> failure is rule generalization, not structure. Consistent live evidence from
> the same day: 9 bounded candidate-loop generations across two
> retry_new_samples cycles (acmegw + newapp), every one 0.0 held-out
> confidence; `GET /api/rules?status=pending_review` stayed empty. This is a
> RECORDED LIMITATION of the M2 default tier on an 8GB host (4096 ctx, CPU
> decode ~1-3 t/s), not a pipeline defect — the fail-closed loop, retry gate,
> attempt ledger, and audit trail all behaved as designed. Default tier P-1
> (qwen3:4b) stands per ruling: flipping would ship a default unverifiable on
> the target box; the formal tier/harness question is assigned to M4.

Measured numbers only (bench/onboarding_eval/sanity_eval.py against a
live Ollama endpoint; the split + generation + validation are the
production code paths).

- model: qwen3:4b
- host CPU: Intel Core i5-10210U (4C/8T; Docker Desktop WSL2 VM, 3.74 GB)
- date: 2026-09-21
- runs per corpus: 1
- per-chat timeout: 1200s (eval-side bound; the production loop is unbounded)

Metric definitions: `valid_json` = SLM responses from which
`extract_json` recovered an object with `pattern` + `field_mappings`;
`compiles` = of those, patterns that compile (`__JSON__` sentinel counts);
`held_out_match` = mean `validate_candidate` held-out match rate over runs
that produced a rule; `mean_attempts` = mean chat() calls per run;
`s/rule` = run wall-clock per stored rule (failed runs included in the
numerator). Split: 5 prompt / up to 15 held-out per corpus.

| corpus  | runs | rules | valid_json | compiles | held_out_match | mean_attempts | s/rule |
| ------- | ---- | ----- | ---------- | -------- | -------------- | ------------- | ------ |
| acmegw  | 1    | 0     | 100.0%     | 100.0%   | n/a            | 3.0           | n/a    |
| zenwall | 1    | 0     | 100.0%     | 100.0%   | n/a            | 3.0           | n/a    |
| newapp  | 1    | 0     | 100.0%     | 100.0%   | n/a            | 3.0           | n/a    |

Note: s/rule values in this recorded run exclude validation time — the
tool's timing window closed before validation ran (corrected after the run;
validation is sub-second regex work over ≤15 lines, and future runs include
it).

acmegw failures:
- 3 attempts: Failed to generate a valid rule for fingerprint 'sanity-eval' after 3 attempts. Last error: Generated rule yielded 0.0 confidence. It failed to match the samples. Try a simpler regex.

zenwall failures:
- 3 attempts: Failed to generate a valid rule for fingerprint 'sanity-eval' after 3 attempts. Last error: Generated rule yielded 0.0 confidence. It failed to match the samples. Try a simpler regex.

newapp failures:
- 3 attempts: Failed to generate a valid rule for fingerprint 'sanity-eval' after 3 attempts. Last error: Generated rule yielded 0.0 confidence. It failed to match the samples. Try a simpler regex.
