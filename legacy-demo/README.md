# legacy-demo (frozen pre-MVP demo)

This directory is the frozen pre-MVP demo: services talk in-process (no
Kafka or Postgres), rules persist to SQLite, and onboarding auto-approves
every generated rule. It is kept for reference only and is not maintained —
see the root README and `docs/` for the real system.

Do not run it on untrusted input: the KV scans here have no timeouts
(M1 ledger, Task 4 note).
