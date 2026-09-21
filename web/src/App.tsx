// web/src/App.tsx — the three-tab M2 shell: Overview (the M1 dashboard),
// Review Queue (Task 8 human review loop) and the Rules registry + audit
// trail (Task 9).
// Tab state is plain useState — no router (air-gapped dashboard: system
// fonts, zero external requests). Same-origin /api only (dev: Vite proxy,
// prod: Caddy) — the gateway ships no CORS.
import { useCallback, useEffect, useState } from 'react'
import { getRaw, getStats } from './api'
import type { EventRow, OcsfEndpoint, RawTrace, Stats } from './types'
import { useEventStream } from './useEventStream'
import ReviewQueue from './ReviewQueue'
import Rules from './Rules'
import './App.css'

const STATS_REFRESH_MS = 5000

type Tab = 'overview' | 'review' | 'rules'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'review', label: 'Review Queue' },
  { id: 'rules', label: 'Rules' },
]

/** parsed / (parsed + unparsed + parse_error + quarantined); "—" before any
 * traffic has been seen (divide-by-zero guard). */
function parsedPercent(byStatus: Stats['by_status']): string {
  const total =
    byStatus.parsed + byStatus.unparsed + byStatus.parse_error + byStatus.quarantined
  if (total === 0) return '—'
  return `${Math.round((byStatus.parsed / total) * 100)}%`
}

function endpointIp(ep: OcsfEndpoint | null): string {
  return ep?.ip ?? '—'
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString()
}

interface StatCard {
  label: string
  value: string | number
}

function statCards(stats: Stats | null): StatCard[] {
  if (stats === null) {
    return [
      { label: 'Events / min', value: '…' },
      { label: 'Parsed', value: '…' },
      { label: 'Unparsed', value: '…' },
      { label: 'Parse errors', value: '…' },
    ]
  }
  const { by_status: byStatus } = stats
  return [
    { label: 'Events / min', value: stats.events_last_minute },
    { label: 'Parsed', value: parsedPercent(byStatus) },
    { label: 'Unparsed', value: byStatus.unparsed },
    { label: 'Parse errors', value: byStatus.parse_error },
  ]
}

/** Side drawer: full OCSF document plus the raw line behind the event
 * (fetched by event_id; the fetch is aborted via AbortController if the
 * drawer closes first). */
function TraceDrawer({ row, onClose }: { row: EventRow; onClose: () => void }) {
  const [trace, setTrace] = useState<RawTrace | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    getRaw(row.event_id, controller.signal)
      .then((t) => setTrace(t))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : String(err))
        }
      })
    return () => controller.abort()
  }, [row.event_id])

  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <aside className="drawer" aria-label={`Traceability for event ${row.event_id}`}>
      <header className="drawer-head">
        <h2>Traceability</h2>
        <button type="button" className="drawer-close" onClick={onClose}>
          Close (Esc)
        </button>
      </header>

      <dl className="kv">
        <dt>Event</dt>
        <dd className="mono">{row.event_id}</dd>
        <dt>Fingerprint</dt>
        <dd className="mono">{row.fingerprint_id}</dd>
        <dt>Status</dt>
        <dd>
          <span className={`badge badge-${row.status}`}>{row.status}</span>
        </dd>
        <dt>Rule version</dt>
        <dd className="mono">{row.rule_version ?? '—'}</dd>
        <dt>Parsed at</dt>
        <dd className="mono">{row.parsed_at}</dd>
      </dl>

      <h3>OCSF document</h3>
      <pre className="code">
        {row.ocsf ? JSON.stringify(row.ocsf, null, 2) : '(event was not parsed)'}
      </pre>

      <h3>Raw line</h3>
      {error !== null && <p className="drawer-error">{error}</p>}
      {error === null && trace === null && <p className="muted">Loading raw…</p>}
      {trace !== null && (
        <>
          <pre className="code">{trace.raw_text}</pre>
          <dl className="kv">
            <dt>Raw ID</dt>
            <dd className="mono">{trace.raw_id}</dd>
            <dt>Source</dt>
            <dd className="mono">{trace.source_id}</dd>
            <dt>Transport</dt>
            <dd className="mono">{trace.transport}</dd>
            <dt>Received at</dt>
            <dd className="mono">{trace.received_at}</dd>
            <dt>Content hash</dt>
            <dd className="mono">{trace.content_hash}</dd>
          </dl>
        </>
      )}
    </aside>
  )
}

/** The M1 Overview page: 4 stat cards, the SSE live-feed table, and the
 * raw-traceability drawer. Unchanged behavior. */
function Overview() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [statsError, setStatsError] = useState<string | null>(null)
  const [selected, setSelected] = useState<EventRow | null>(null)
  const rows = useEventStream()

  const refreshStats = useCallback(() => {
    getStats()
      .then((s) => {
        setStats(s)
        setStatsError(null)
      })
      .catch((err: unknown) => {
        setStatsError(err instanceof Error ? err.message : String(err))
      })
  }, [])

  useEffect(() => {
    refreshStats()
    const timer = setInterval(refreshStats, STATS_REFRESH_MS)
    return () => clearInterval(timer)
  }, [refreshStats])

  return (
    <section aria-label="Overview">
      <header className="topbar">
        <h1>ULPF Overview</h1>
        <span className="muted">live feed · {rows.length} rows shown (cap 200)</span>
      </header>

      {statsError !== null && (
        <p className="banner-error" role="alert">
          stats unavailable: {statsError}
        </p>
      )}

      <section className="cards">
        {statCards(stats).map((card) => (
          <div className="card" key={card.label}>
            <div className="card-value">{card.value}</div>
            <div className="card-label">{card.label}</div>
          </div>
        ))}
      </section>

      <section className="feed">
        <table className="feed-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Fingerprint</th>
              <th>Status</th>
              <th>Source → Destination</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.event_id} onClick={() => setSelected(row)} tabIndex={0}
                  onKeyDown={(ev) => { if (ev.key === 'Enter') setSelected(row) }}>
                <td className="mono">{formatTime(row.parsed_at)}</td>
                <td className="mono">{row.fingerprint_id}</td>
                <td>
                  <span className={`badge badge-${row.status}`}>{row.status}</span>
                </td>
                <td className="mono">
                  {endpointIp(row.ocsf?.src_endpoint ?? null)} →{' '}
                  {endpointIp(row.ocsf?.dst_endpoint ?? null)}
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={4} className="muted empty">
                  Waiting for events on /api/stream/events…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

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

export default function App() {
  const [tab, setTab] = useState<Tab>('overview')

  return (
    <div className="app">
      <nav className="tabs" role="tablist" aria-label="ULPF sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? 'tab tab-active' : 'tab'}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>
      {tab === 'overview' && <Overview />}
      {tab === 'review' && <ReviewQueue />}
      {tab === 'rules' && <Rules />}
    </div>
  )
}
