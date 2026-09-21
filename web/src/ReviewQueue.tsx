// web/src/ReviewQueue.tsx — the human rule-review loop (Task 8 hero page).
//
// Fetches every pending_review candidate (GET /api/rules?status=pending_review)
// on mount and after every action, and renders one card per candidate:
//   - the Task-3 gate's checks grid — check keys rendered VERBATIM (Task 3
//     ruling: `caps_and_allowlist` may be false for cap, allow-list OR
//     per-sample schema failures, so the key itself is the contract);
//   - before/after preview pairs (held-out line + parsed OCSF JSON);
//   - confidence AND validation.held_out_match_rate (T5-f: SLM confidence is
//     prompt-only and optimistic — the held-out rate is the honest number);
//   - a mapping editor whose edits travel as `edited_mappings`;
//   - an override pattern textarea whose contents travel as `override`;
//   - actor/reason inputs and Approve/Reject with disabled-while-submitting
//     and an error banner on non-2xx.
//
// Air-gap rules: same-origin /api only, system fonts, zero external requests.
import { useCallback, useEffect, useState } from 'react'
import { getRules, postJson } from './api'
import type { ApproveBody, RejectBody, RuleMapping, RuleRow } from './types'

const PENDING_STATUS = 'pending_review'

function pct(rate: number): string {
  return `${Math.round(rate * 100)}%`
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

/** The gate's checks grid: verbatim key names, one ✓ or ✗ per check. */
function ChecksGrid({ validation }: { validation: NonNullable<RuleRow['validation']> }) {
  return (
    <div className="checks">
      <h3>Validation checks</h3>
      <ul className="checks-grid">
        {Object.entries(validation.checks).map(([key, ok]) => (
          <li className="check" key={key}>
            <span className={`check-mark ${ok ? 'check-ok' : 'check-fail'}`}>
              {ok ? '✓' : '✗'}
            </span>
            <span className="mono">{key}</span>
          </li>
        ))}
      </ul>
      {validation.notes.length > 0 && (
        <ul className="notes">
          {validation.notes.map((note, i) => (
            <li key={i}>{note}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** Before/after pairs: the held-out sample line and what the candidate's
 * parser produced for it (pretty-printed OCSF, or a parse-error badge). */
function Previews({ validation }: { validation: NonNullable<RuleRow['validation']> }) {
  if (validation.previews.length === 0) return null
  return (
    <div className="previews">
      <h3>Previews (held-out line → OCSF)</h3>
      {validation.previews.map((p, i) => (
        <div className="preview" key={i}>
          <pre className="code">{p.line}</pre>
          <span className={`badge badge-${p.status}`}>{p.status}</span>
          <pre className="code">
            {p.ocsf !== null ? JSON.stringify(p.ocsf, null, 2) : '(line failed to parse)'}
          </pre>
        </div>
      ))}
    </div>
  )
}

/** Editable source_field/ocsf_path rows: add, edit, remove before approving.
 * Changes only travel to the gateway when they differ from the candidate. */
function MappingEditor({
  mappings,
  onChange,
}: {
  mappings: RuleMapping[]
  onChange: (next: RuleMapping[]) => void
}) {
  const update = (index: number, key: keyof RuleMapping, value: string) => {
    onChange(mappings.map((m, i) => (i === index ? { ...m, [key]: value } : m)))
  }
  return (
    <div className="mapping-editor">
      <div className="mapping-head">
        <span className="mono muted">source_field</span>
        <span className="mono muted">ocsf_path</span>
        <span />
      </div>
      {mappings.map((m, i) => (
        <div className="mapping-row" key={i}>
          <input
            className="mono"
            aria-label={`source_field row ${i + 1}`}
            value={m.source_field}
            onChange={(e) => update(i, 'source_field', e.target.value)}
          />
          <input
            className="mono"
            aria-label={`ocsf_path row ${i + 1}`}
            value={m.ocsf_path}
            onChange={(e) => update(i, 'ocsf_path', e.target.value)}
          />
          <button
            type="button"
            onClick={() => onChange(mappings.filter((_, j) => j !== i))}
          >
            Remove row {i + 1}
          </button>
        </div>
      ))}
      <button
        type="button"
        className="add-mapping"
        onClick={() => onChange([...mappings, { source_field: '', ocsf_path: '' }])}
      >
        Add mapping
      </button>
    </div>
  )
}

/** One pending candidate with its review controls. */
function CandidateCard({ rule, onDone }: { rule: RuleRow; onDone: () => void }) {
  const [mappings, setMappings] = useState<RuleMapping[]>(() =>
    rule.mappings.map((m) => ({ ...m })),
  )
  const [overrideOn, setOverrideOn] = useState(false)
  const [overridePattern, setOverridePattern] = useState(rule.pattern)
  const [actor, setActor] = useState('anonymous')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const actorValue = actor.trim() === '' ? 'anonymous' : actor.trim()
  const reasonValue = reason.trim()
  const mappingsChanged =
    JSON.stringify(mappings) !== JSON.stringify(rule.mappings)

  const approveBody = (): ApproveBody => {
    const body: ApproveBody = { actor: actorValue }
    if (reasonValue !== '') body.reason = reasonValue
    if (overrideOn) {
      // override wins wholesale: pattern textarea + current editor rows
      body.override = { pattern: overridePattern, mappings }
    } else if (mappingsChanged) {
      body.edited_mappings = mappings
    }
    return body
  }

  const rejectBody = (): RejectBody => {
    const body: RejectBody = { actor: actorValue }
    if (reasonValue !== '') body.reason = reasonValue
    return body
  }

  const act = (action: 'approve' | 'reject') => {
    setSubmitting(true)
    setError(null)
    const url = `/api/rules/${encodeURIComponent(rule.fingerprint_id)}/candidates/${rule.id}/${action}`
    postJson(url, action === 'approve' ? approveBody() : rejectBody())
      .then(() => onDone()) // refetch — the card leaves the queue
      .catch((err: unknown) => setError(errorMessage(err)))
      .finally(() => setSubmitting(false))
  }

  return (
    <article className="card candidate" aria-label={`Candidate for ${rule.fingerprint_id}`}>
      <header className="candidate-head">
        <h3 className="mono">{rule.fingerprint_id}</h3>
        <span className={`badge badge-${rule.provenance}`}>{rule.provenance}</span>
        <span className="muted">v{rule.version}</span>
      </header>

      <dl className="kv">
        <dt>Confidence</dt>
        <dd>
          <span className="confidence">{rule.confidence ?? '—'}</span>
          {rule.provenance === 'slm' && (
            <span className="muted"> (prompt-only, optimistic — see held-out rate)</span>
          )}
        </dd>
        {rule.validation !== null && (
          <>
            <dt>Held-out match</dt>
            <dd className="held-out-rate">{pct(rule.validation.held_out_match_rate)}</dd>
          </>
        )}
        <dt>Created by</dt>
        <dd className="mono">{rule.created_by}</dd>
      </dl>

      <h3>Pattern</h3>
      {overrideOn ? (
        <textarea
          className="code override-pattern"
          aria-label="override pattern"
          value={overridePattern}
          rows={4}
          onChange={(e) => setOverridePattern(e.target.value)}
        />
      ) : (
        <pre className="code">{rule.pattern}</pre>
      )}

      <h3>Mappings</h3>
      <MappingEditor mappings={mappings} onChange={setMappings} />

      {rule.validation !== null && (
        <>
          <ChecksGrid validation={rule.validation} />
          <Previews validation={rule.validation} />
        </>
      )}

      <div className="review-actions">
        <label>
          <span className="muted">Actor</span>
          <input
            aria-label="actor"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
          />
        </label>
        <label>
          <span className="muted">Reason</span>
          <input
            aria-label="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </label>
      </div>

      {error !== null && (
        <p className="banner-error" role="alert">
          {error}
        </p>
      )}

      <div className="review-buttons">
        <button
          type="button"
          className="approve"
          disabled={submitting}
          onClick={() => act('approve')}
        >
          Approve
        </button>
        <button
          type="button"
          className="reject"
          disabled={submitting}
          onClick={() => act('reject')}
        >
          Reject
        </button>
        <button
          type="button"
          className="override-toggle"
          disabled={submitting}
          onClick={() => setOverrideOn((on) => !on)}
        >
          {overrideOn ? 'Cancel override' : 'Override pattern'}
        </button>
      </div>
    </article>
  )
}

/** The Review Queue tab: pending candidates, refetched after every action. */
export default function ReviewQueue() {
  const [rules, setRules] = useState<RuleRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reloadTick, setReloadTick] = useState(0)

  useEffect(() => {
    let alive = true
    getRules({ status: PENDING_STATUS })
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

  return (
    <section aria-label="Review Queue">
      <header className="topbar">
        <h1>Review Queue</h1>
        <span className="muted">
          {rules === null ? '…' : rules.length} candidate(s) pending review
        </span>
      </header>

      {error !== null && (
        <p className="banner-error" role="alert">
          candidates unavailable: {error}{' '}
          <button type="button" onClick={refresh}>
            Retry
          </button>
        </p>
      )}

      {rules === null && error === null && (
        <p className="muted empty">Loading pending candidates…</p>
      )}

      {rules !== null && rules.length === 0 && (
        <p className="muted empty">
          No pending candidates — every fingerprint has an active rule or its
          candidate was rejected.
        </p>
      )}

      {rules?.map((rule) => (
        <CandidateCard key={rule.id} rule={rule} onDone={refresh} />
      ))}
    </section>
  )
}
