// web/src/Rules.tsx — the Rules registry + audit trail page (Task 9).
//
// Fetches EVERY rule row (GET /api/rules, no status filter — the registry
// shows all statuses) and renders one summary row per fingerprint: its latest
// version, with status/provenance badges and the activation timestamp.
// Expanding a fingerprint fires BOTH GET /api/rules/{fp} (the version
// timeline) and GET /api/audit?fingerprint=… (the audit feed); the history
// response's embedded audit array is redundant and goes unused (Task 9
// ruling). Deactivate POSTs the gateway's /api/rules/{fp}/deactivate with
// {actor: "anonymous"} and refetches the list so the row's badge flips.
//
// Audit action strings are the gateway's closed CHECK vocabulary and are
// rendered VERBATIM — the string IS the label (same ruling as the checks
// grid: samples_split, candidate_created, candidate_failed, rule_approved,
// rule_rejected, rule_deactivated, rule_reactivated, reparse_complete).
//
// Air-gap rules: same-origin /api only, system fonts, zero external requests.
import { useCallback, useEffect, useState } from 'react'
import { getAudit, getRuleHistory, getRules, postJson } from './api'
import type { AuditRow, RuleRow } from './types'

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** Collapse the rule rows to one per fingerprint — its latest version (the
 * gateway orders version DESC within a fingerprint; the max() makes the
 * grouping independent of that ordering). */
function latestPerFingerprint(rules: RuleRow[]): RuleRow[] {
  const latest = new Map<string, RuleRow>()
  for (const rule of rules) {
    const current = latest.get(rule.fingerprint_id)
    if (current === undefined || rule.version > current.version) {
      latest.set(rule.fingerprint_id, rule)
    }
  }
  return [...latest.values()].sort((a, b) =>
    a.fingerprint_id.localeCompare(b.fingerprint_id),
  )
}

/** The expanded detail under a summary row: the version timeline (every
 * stored version, newest first) plus the audit feed. The component only
 * exists while the row is expanded — collapsing unmounts it, so re-expanding
 * (or retrying after an error) starts from null state and refetches. */
function FingerprintDetail({ fingerprintId }: { fingerprintId: string }) {
  const [history, setHistory] = useState<RuleRow[] | null>(null)
  const [audit, setAudit] = useState<AuditRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    getRuleHistory(fingerprintId)
      .then((res) => {
        // res.audit (the history endpoint's embedded trail) goes unused:
        // the feed below comes from getAudit — one source, one cache
        if (alive) setHistory(res.rules)
      })
      .catch((err: unknown) => {
        if (alive) setError(errorMessage(err))
      })
    getAudit(fingerprintId)
      .then((res) => {
        if (alive) setAudit(res.audit)
      })
      .catch((err: unknown) => {
        if (alive) setError(errorMessage(err))
      })
    return () => {
      alive = false
    }
  }, [fingerprintId])

  return (
    <>
      <h3>Version timeline</h3>
      {error !== null && (
        <p className="banner-error" role="alert">
          history unavailable: {error}
        </p>
      )}
      {history === null && error === null && (
        <p className="muted">Loading versions…</p>
      )}
      {history !== null && (
        <ul className="version-timeline">
          {history.map((rule) => (
            <li key={rule.id}>
              <span className="mono">v{rule.version}</span>
              <span className={`badge badge-${rule.status}`}>{rule.status}</span>
              <span className={`badge badge-${rule.provenance}`}>
                {rule.provenance}
              </span>
              <span className="mono muted">
                {rule.activated_at ?? 'not activated'}
              </span>
            </li>
          ))}
        </ul>
      )}

      <h3>Audit trail</h3>
      {audit === null && error === null && (
        <p className="muted">Loading audit…</p>
      )}
      {audit !== null && audit.length === 0 && (
        <p className="muted">No audit entries for this fingerprint.</p>
      )}
      {audit !== null && audit.length > 0 && (
        <ul className="audit-feed">
          {audit.map((row) => (
            <li key={row.id}>
              <span className="mono">{row.ts}</span>
              <span className="audit-sep"> · </span>
              <span>{row.actor}</span>
              <span className="audit-sep"> · </span>
              <span className="mono">{row.action}</span>
            </li>
          ))}
        </ul>
      )}
    </>
  )
}

/** One fingerprint: the clickable summary row (latest version) plus, when
 * expanded, the version-timeline + audit-feed detail row. The Deactivate
 * button shows only while the latest version is active. */
function FingerprintGroup({
  rule,
  refresh,
}: {
  rule: RuleRow
  refresh: () => void
}) {
  const [open, setOpen] = useState(false)
  const [deactivating, setDeactivating] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const toggle = () => setOpen((o) => !o)

  const deactivate = () => {
    setDeactivating(true)
    setActionError(null)
    postJson(
      `/api/rules/${encodeURIComponent(rule.fingerprint_id)}/deactivate`,
      { actor: 'anonymous' },
    )
      .then(() => refresh()) // refetch — the row's badge flips
      .catch((err: unknown) => setActionError(errorMessage(err)))
      .finally(() => setDeactivating(false))
  }

  return (
    <tbody>
      <tr
        onClick={toggle}
        onKeyDown={(ev) => {
          if (ev.key === 'Enter') toggle()
        }}
        tabIndex={0}
        aria-expanded={open}
      >
        <td className="mono">{rule.fingerprint_id}</td>
        <td className="mono">v{rule.version}</td>
        <td>
          <span className={`badge badge-${rule.status}`}>{rule.status}</span>
        </td>
        <td>
          <span className={`badge badge-${rule.provenance}`}>
            {rule.provenance}
          </span>
        </td>
        <td className="mono muted">{rule.activated_at ?? '—'}</td>
        <td>
          {rule.status === 'active' && (
            <button
              type="button"
              className="deactivate"
              disabled={deactivating}
              onClick={(ev) => {
                ev.stopPropagation() // the row click toggles; the button must not
                deactivate()
              }}
            >
              Deactivate
            </button>
          )}
        </td>
      </tr>
      {actionError !== null && (
        <tr className="rules-error-row">
          <td colSpan={6}>
            <p className="banner-error" role="alert">
              deactivate failed: {actionError}
            </p>
          </td>
        </tr>
      )}
      {open && (
        <tr className="rules-detail-row">
          <td colSpan={6}>
            <div className="rules-detail">
              <FingerprintDetail fingerprintId={rule.fingerprint_id} />
            </div>
          </td>
        </tr>
      )}
    </tbody>
  )
}

/** The Rules tab: the whole registry (every status), one row per
 * fingerprint, expandable to its version timeline + audit feed. */
export default function Rules() {
  const [rules, setRules] = useState<RuleRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reloadTick, setReloadTick] = useState(0)

  useEffect(() => {
    let alive = true
    getRules() // no status filter — the registry shows every status
      .then((res) => {
        if (!alive) return
        setRules(res.rules)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!alive) return
        setError(errorMessage(err))
      })
    return () => {
      alive = false
    }
  }, [reloadTick])

  const refresh = useCallback(() => setReloadTick((n) => n + 1), [])
  const rows = rules === null ? null : latestPerFingerprint(rules)

  return (
    <section aria-label="Rules">
      <header className="topbar">
        <h1>Rules</h1>
        <span className="muted">
          {rows === null ? '…' : rows.length} fingerprint(s) registered
        </span>
      </header>

      {error !== null && (
        <p className="banner-error" role="alert">
          rules unavailable: {error}{' '}
          <button type="button" onClick={refresh}>
            Retry
          </button>
        </p>
      )}

      {rows === null && error === null && (
        <p className="muted empty">Loading rule registry…</p>
      )}

      {rows !== null && rows.length === 0 && (
        <p className="muted empty">
          No rules yet — a fingerprint appears here once onboarding has parsed
          its samples into a rule.
        </p>
      )}

      {rows !== null && rows.length > 0 && (
        <section className="feed">
          <table className="feed-table rules-table">
            <thead>
              <tr>
                <th>Fingerprint</th>
                <th>Version</th>
                <th>Status</th>
                <th>Provenance</th>
                <th>Activated at</th>
                <th>Actions</th>
              </tr>
            </thead>
            {rows.map((rule) => (
              <FingerprintGroup
                key={rule.fingerprint_id}
                rule={rule}
                refresh={refresh}
              />
            ))}
          </table>
        </section>
      )}
    </section>
  )
}
