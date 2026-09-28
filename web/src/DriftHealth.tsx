// web/src/DriftHealth.tsx — the Drift & Health page (M3 Task 10, the fifth
// and final §12 page): field health across the latest closed drift windows,
// the merged enforcement/alert feed, and unmapped.* extension opportunities.
//
// Two fetches fire together on mount and after every action (one effect, one
// alive flag, Promise.all — one shared Retry banner when either fails). The
// alerts endpoint (ruling P-4) already merges window rows and audit actions
// into ONE latest-first list — this page renders that array verbatim,
// discriminated only by the `kind` field, and never re-merges or re-sorts
// client-side.
//
// Un-quarantine gating (ruling P-8): once the metrics land, one
// getRuleHistory(fp) per DISTINCT fingerprint they name supplies the ACTIVE
// version's quarantined_fields — the authoritative quarantine state (the
// gateway now exposes the column on every rule row; migration 001's
// rules_one_active partial unique index guarantees at most one active
// version per fingerprint, and the un-quarantine POST itself 409s unless the
// rule is active, so a fingerprint with no active version gates nothing).
// The histories load with the feeds or fail the page as a unit.
//
// Air-gap rules: same-origin /api only, system fonts, zero external requests.
import { useCallback, useEffect, useState } from 'react'
import { getDriftAlerts, getDriftMetrics, getRuleHistory, postJson } from './api'
import type {
  AuditRow,
  DriftAlertRow,
  DriftMetricRow,
  RuleHistoryResponse,
} from './types'
import { formatTime } from './cells'

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** 0..1 rate -> rounded percentage; '—' where the window measures no rate. */
function pctOrNull(rate: number | null): string {
  return rate === null ? '—' : `${Math.round(rate * 100)}%`
}

/** "Shape top class" = the argmax key of shape_dist; '—' when the histogram
 * is empty or null (no observed values / __rule__ rows). */
function shapeTop(dist: Record<string, number> | null): string {
  if (dist === null) return '—'
  let best: string | null = null
  let bestCount = -1
  for (const [cls, count] of Object.entries(dist)) {
    if (count > bestCount) {
      best = cls
      bestCount = count
    }
  }
  return best ?? '—'
}

/** detail.field of an audit row, when the action carried one
 * (rule_deactivated details name the rule, not a field). */
function auditField(row: AuditRow): string | undefined {
  if (row.detail === null) return undefined
  const detail = row.detail as { field?: unknown }
  return typeof detail.field === 'string' ? detail.field : undefined
}

/** Currently-quarantined fields per fingerprint, from each fingerprint's
 * rule history (ruling P-8): the ACTIVE version's quarantined_fields — not
 * the newest version's, which may be a deactivated row still carrying the
 * list. Fingerprints with no active version gate nothing. */
function quarantinedByFingerprint(
  histories: RuleHistoryResponse[],
): Map<string, Set<string>> {
  const quarantined = new Map<string, Set<string>>()
  for (const { rules } of histories) {
    const active = rules.find((rule) => rule.status === 'active')
    if (active !== undefined) {
      quarantined.set(active.fingerprint_id, new Set(active.quarantined_fields))
    }
  }
  return quarantined
}

/** Stable React key for a merged-feed row (window rows key on the
 * deterministic drift_windows key; audit rows on their audit id). */
function alertKey(row: DriftAlertRow): string {
  return row.kind === 'window'
    ? `window:${row.fingerprint_id}:${row.rule_version}:${row.field}:${row.window_start}`
    : `audit:${row.id}`
}

/** One Field-health row: the latest closed window for a (fingerprint, field).
 * The Un-quarantine button (human override, actor "ui") shows only while the
 * field sits in the active rule's quarantined_fields (P-8); its POST
 * refetches the feeds and histories so the gate, the badges and the
 * enforcement feed all move together. */
function FieldHealthRow({
  row,
  quarantined,
  refresh,
}: {
  row: DriftMetricRow
  quarantined: boolean
  refresh: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  const unquarantine = () => {
    setBusy(true)
    setActionError(null)
    postJson(`/api/rules/${encodeURIComponent(row.fingerprint_id)}/unquarantine`, {
      field: row.field,
      actor: 'ui',
    })
      .then(() => refresh()) // refetch — the gate recomputes, the button leaves
      .catch((err: unknown) => setActionError(errorMessage(err)))
      .finally(() => setBusy(false))
  }

  return (
    <>
      <tr>
        <td className="mono">{row.fingerprint_id}</td>
        <td className="mono">{row.field}</td>
        <td>
          <span className={`badge badge-${row.severity}`}>{row.severity}</span>
        </td>
        <td className="mono">{pctOrNull(row.null_rate)}</td>
        <td className="mono">{pctOrNull(row.match_rate)}</td>
        <td className="mono">{pctOrNull(row.violation_rate)}</td>
        <td className="mono">{shapeTop(row.shape_dist)}</td>
        <td className="mono">{row.events_count}</td>
        <td className="mono">{formatTime(row.window_end)}</td>
        <td>
          <span className="mono">{row.action_taken ?? '—'}</span>
          {quarantined && (
            <button
              type="button"
              className="unquarantine"
              disabled={busy}
              onClick={unquarantine}
            >
              Un-quarantine
            </button>
          )}
        </td>
      </tr>
      {actionError !== null && (
        <tr className="drift-error-row">
          <td colSpan={10}>
            <p className="banner-error" role="alert">
              un-quarantine failed: {actionError}
            </p>
          </td>
        </tr>
      )}
    </>
  )
}

/** The Drift & Health tab: field health, the merged enforcement feed, and
 * unmapped.* extension opportunities. */
export default function DriftHealth() {
  const [metrics, setMetrics] = useState<DriftMetricRow[] | null>(null)
  const [alerts, setAlerts] = useState<DriftAlertRow[] | null>(null)
  const [quarantined, setQuarantined] = useState<Map<string, Set<string>> | null>(
    null,
  )
  const [error, setError] = useState<string | null>(null)
  const [reloadTick, setReloadTick] = useState(0)

  useEffect(() => {
    let alive = true
    // Both feeds as a unit; the rule histories follow the metrics (their
    // fingerprints come from them) and the un-quarantine gate (P-8) loads
    // with the rest or fails the page — one shared Retry banner.
    Promise.all([getDriftMetrics(), getDriftAlerts()])
      .then(([metricsRes, alertsRes]) => {
        const fingerprints = [
          ...new Set(metricsRes.metrics.map((row) => row.fingerprint_id)),
        ]
        return Promise.all(fingerprints.map((fp) => getRuleHistory(fp))).then(
          (histories) => [metricsRes, alertsRes, histories] as const,
        )
      })
      .then(([metricsRes, alertsRes, histories]) => {
        if (!alive) return
        setMetrics(metricsRes.metrics)
        setAlerts(alertsRes.alerts)
        setQuarantined(quarantinedByFingerprint(histories))
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

  const opportunities =
    metrics === null ? null : metrics.filter((r) => r.field.startsWith('unmapped.'))

  return (
    <section aria-label="Drift & Health">
      <header className="topbar">
        <h1>Drift &amp; Health</h1>
        <span className="muted">
          {metrics === null ? '…' : metrics.length} field signal(s) ·{' '}
          {alerts === null ? '…' : alerts.length} alert(s)
        </span>
      </header>

      {error !== null && (
        <p className="banner-error" role="alert">
          drift data unavailable: {error}{' '}
          <button type="button" onClick={refresh}>
            Retry
          </button>
        </p>
      )}

      {metrics === null && alerts === null && error === null && (
        <p className="muted empty">Loading drift data…</p>
      )}

      <section className="drift-section" aria-label="Field health">
        <h2>Field health</h2>
        {metrics === null && error === null && (
          <p className="muted">Loading windows…</p>
        )}
        {metrics !== null && metrics.length === 0 && (
          <p className="muted empty">
            No closed drift windows yet — field health appears once the drift
            loop has closed a window.
          </p>
        )}
        {metrics !== null && metrics.length > 0 && (
          <section className="feed">
            <table className="feed-table drift-table">
              <thead>
                <tr>
                  <th>Fingerprint</th>
                  <th>Field</th>
                  <th>Severity</th>
                  <th>Null</th>
                  <th>Match</th>
                  <th>Violation</th>
                  <th>Shape top</th>
                  <th>Events</th>
                  <th>Window end</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {metrics.map((row) => (
                  <FieldHealthRow
                    key={`${row.fingerprint_id}:${row.rule_version}:${row.field}`}
                    row={row}
                    quarantined={quarantined
                      ?.get(row.fingerprint_id)
                      ?.has(row.field) ?? false}
                    refresh={refresh}
                  />
                ))}
              </tbody>
            </table>
          </section>
        )}
      </section>

      <section className="drift-section" aria-label="Enforcement feed">
        <h2>Enforcement feed</h2>
        {alerts === null && error === null && (
          <p className="muted">Loading alerts…</p>
        )}
        {alerts !== null && alerts.length === 0 && (
          <p className="muted empty">
            No drift alerts or enforcement actions yet — windows below the
            severity thresholds and quiet enforcement show nothing here.
          </p>
        )}
        {alerts !== null && alerts.length > 0 && (
          <ul className="audit-feed drift-feed">
            {alerts.map((row) => (
              <li key={alertKey(row)} className="drift-feed-item">
                {row.kind === 'window' ? (
                  <>
                    <span className="mono">{row.window_start}</span>
                    <span className="audit-sep"> · </span>
                    <span className="mono">{row.fingerprint_id}</span>
                    <span className="audit-sep"> · </span>
                    <span className="mono">{row.field}</span>
                    <span className="audit-sep"> · </span>
                    <span className={`badge badge-${row.severity}`}>
                      {row.severity}
                    </span>
                    <span className="audit-sep"> · </span>
                    <span className="mono">{row.action_taken ?? '—'}</span>
                  </>
                ) : (
                  <>
                    <span className="mono">{row.ts}</span>
                    <span className="audit-sep"> · </span>
                    <span>{row.actor}</span>
                    <span className="audit-sep"> · </span>
                    <span className="mono">{row.action}</span>
                    <span className="audit-sep"> · </span>
                    <span className="mono">{row.entity}</span>
                    <span className="audit-sep"> · </span>
                    <span className="mono">{auditField(row) ?? '—'}</span>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="drift-section" aria-label="Extension opportunities">
        <h2>Extension opportunities</h2>
        {opportunities === null && error === null && (
          <p className="muted">Loading opportunities…</p>
        )}
        {opportunities !== null && opportunities.length === 0 && (
          <p className="muted empty">No unmapped telemetry keys observed.</p>
        )}
        {opportunities !== null && opportunities.length > 0 && (
          <section className="cards">
            {opportunities.map((row) => (
              <article
                className="card opportunity"
                key={`opportunity:${row.fingerprint_id}:${row.rule_version}:${row.field}`}
                aria-label={`Opportunity ${row.fingerprint_id} ${row.field}`}
              >
                <h3>new telemetry key observed</h3>
                <p className="mono">{row.field}</p>
                <p className="muted">
                  <span className="mono">{row.fingerprint_id}</span> ·{' '}
                  {row.events_count} events · window ended{' '}
                  {formatTime(row.window_end)}
                </p>
                <p>
                  <span className={`badge badge-${row.severity}`}>
                    {row.severity}
                  </span>{' '}
                  <span className="mono muted">{row.action_taken ?? '—'}</span>
                </p>
              </article>
            ))}
          </section>
        )}
      </section>
    </section>
  )
}
