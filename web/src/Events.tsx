// web/src/Events.tsx — the Events browser (M3 Task 9, the fourth §12 page):
// a filterable current-view table (GET /api/events) with the raw↔normalized
// drill-down drawer shared with Overview (components/TraceDrawer).
//
// Filters refetch live: status / fingerprint / limit are useEffect deps, so
// every change re-fires the fetch (empty-string status and fingerprint are
// forwarded as undefined — no filter). The Reload button and the error
// banner's Retry bump the same reloadTick the M2 pages use. Rows reuse the
// Overview interaction pattern: click or Enter opens the drawer, keyed by
// event_id so switching rows remounts it.
//
// Air-gap rules: same-origin /api only, system fonts, zero external requests.
import { useCallback, useEffect, useState } from 'react'
import { getEvents } from './api'
import type { EventRow } from './types'
import { endpointIp, formatTime } from './cells'
import TraceDrawer from './components/TraceDrawer'

/** The Events tab: filter bar + current-view table + traceability drawer. */
export default function Events() {
  const [status, setStatus] = useState('')
  const [fingerprint, setFingerprint] = useState('')
  const [limit, setLimit] = useState(50)
  const [events, setEvents] = useState<EventRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [reloadTick, setReloadTick] = useState(0)
  const [selected, setSelected] = useState<EventRow | null>(null)

  useEffect(() => {
    let alive = true
    getEvents({
      status: status || undefined,
      fingerprint: fingerprint || undefined,
      limit,
    })
      .then((res) => {
        if (!alive) return
        setEvents(res.events)
        setError(null)
      })
      .catch((err: unknown) => {
        if (!alive) return
        setError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      alive = false
    }
  }, [status, fingerprint, limit, reloadTick])

  const refresh = useCallback(() => setReloadTick((n) => n + 1), [])

  return (
    <section aria-label="Events">
      <header className="topbar">
        <h1>Events</h1>
        <span className="muted">
          {events === null ? '…' : events.length} event(s) in the current view
        </span>
      </header>

      <div className="filters">
        <label>
          <span className="muted">Status</span>
          <select
            aria-label="status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">All</option>
            <option value="parsed">parsed</option>
            <option value="unparsed">unparsed</option>
            <option value="parse_error">parse_error</option>
            <option value="quarantined">quarantined</option>
          </select>
        </label>
        <label>
          <span className="muted">Fingerprint</span>
          <input
            aria-label="fingerprint"
            value={fingerprint}
            placeholder="fp-…"
            onChange={(e) => setFingerprint(e.target.value)}
          />
        </label>
        <label>
          <span className="muted">Limit</span>
          <select
            aria-label="limit"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
          >
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={500}>500</option>
          </select>
        </label>
        <button type="button" onClick={refresh}>
          Reload
        </button>
      </div>

      {error !== null && (
        <p className="banner-error" role="alert">
          events unavailable: {error}{' '}
          <button type="button" onClick={refresh}>
            Retry
          </button>
        </p>
      )}

      {events === null && error === null && (
        <p className="muted empty">Loading events…</p>
      )}

      {events !== null && events.length === 0 && (
        <p className="muted empty">No events match the current filters.</p>
      )}

      {events !== null && events.length > 0 && (
        <section className="feed">
          <table className="feed-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Fingerprint</th>
                <th>Status</th>
                <th>Rule v</th>
                <th>Source → Destination</th>
              </tr>
            </thead>
            <tbody>
              {events.map((row) => (
                <tr key={row.event_id} onClick={() => setSelected(row)} tabIndex={0}
                    onKeyDown={(ev) => { if (ev.key === 'Enter') setSelected(row) }}>
                  <td className="mono">{formatTime(row.parsed_at)}</td>
                  <td className="mono">{row.fingerprint_id}</td>
                  <td>
                    <span className={`badge badge-${row.status}`}>{row.status}</span>
                  </td>
                  <td className="mono">{row.rule_version ?? '—'}</td>
                  <td className="mono">
                    {endpointIp(row.ocsf?.src_endpoint ?? null)} →{' '}
                    {endpointIp(row.ocsf?.dst_endpoint ?? null)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {selected !== null && (
        <TraceDrawer
          key={selected.event_id}
          row={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </section>
  )
}
