// web/src/components/TraceDrawer.tsx — the shared raw↔normalized traceability
// drawer, extracted VERBATIM from App.tsx (M3 Task 9) so the Overview feed
// and the Events browser both drill into the raw line behind an event.
// Behavior, props and markup are unchanged — only the location moved.
import { useEffect, useState } from 'react'
import { getRaw } from '../api'
import type { EventRow, RawTrace } from '../types'

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

export default TraceDrawer
