# Onboarding Engine (`onboarding/`)

Generates a candidate parsing rule for a new, unrecognized log format
using a local small language model (SLM), from a handful of raw sample
lines — no fine-tuning, no labeled training data.

## Core function

```python
# onboarding/generate_rule.py
def generate_rule(fingerprint_id: str, sample_lines: list[str]) -> Rule:
```

Given 5-20 raw sample lines believed to be the same format, this:
1. Detects JSON programmatically up front and routes it to a
   deterministic path (see below) — no model call needed for JSON at
   all, since it's already self-describing.
2. For everything else, prompts a local SLM (via Ollama) for a regex
   with named capture groups, and a mapping from each captured field to
   an OCSF field path.
3. Computes a confidence score by re-running the generated pattern
   against the sample lines and checking how many actually match with
   every expected field populated.

Returns a `Rule` with `provenance="slm-generated"`.

## Design decisions worth knowing

- **Runtime:** Ollama, running locally — `ibm/granite4.1:3b` in
  testing, `granite4.1:8b` as a fallback for harder formats needing more
  reliable structured output.
- **Extension-blob parsing over field-by-field regex.** Rather than
  asking the model to write a regex that captures every key=value pair
  in the exact order it appears (which proved unreliable — the model
  would scramble field order on more varied sample sets), the pattern
  captures the whole extension as one blob, and a deterministic
  post-processing step splits it into key=value pairs. This sidesteps
  an entire class of ordering bugs.
- **JSON bypasses the model entirely.** JSON is flattened into dotted
  paths and matched against known field-name aliases
  (`src_ip`/`source_ip`/`srcip` → `src_endpoint.ip`, etc.) with zero
  model calls — more reliable and much faster than asking an SLM to
  reverse-engineer a regex for data that's already structured.
- **Prompt sample cap.** Only the first 5 sample lines are shown to the
  model, even if more are provided — feeding a small model too many
  varied examples at once caused it to lose track of details (like
  field order) that fewer, well-chosen examples preserved. Confidence is
  still checked against the *full* sample set, so this doesn't weaken
  validation, only what the model has to read.
- **Multi-turn retry with escalating temperature.** Failed attempts feed
  their error back to the model for self-correction rather than blindly
  retrying with an identical prompt.
- **No fine-tuning.** The system needs to generalize to formats it has
  never seen; fine-tuning on a handful of known formats would optimize
  for the wrong thing. This is a deliberate architectural choice, not an
  oversight — see the idea presentation's innovation section for the
  research this design is grounded in (Matryoshka, DeepParse).

## Known limitation

Formats where a single field combines two logically distinct values
(e.g. `source=203.0.113.45:51422`, combining IP and port) aren't
currently splittable, since `FieldMapping` is one source field to one
OCSF path. Left as-is deliberately — this is exactly the case the
human-override path exists for.