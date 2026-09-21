# services/drift — M3 drift-detection service (cold path, Postgres only):
# stateless window recompute from the current view, tier-1 invariants from
# event zero, INSERT-only drift_windows writes (plan Task 4).
