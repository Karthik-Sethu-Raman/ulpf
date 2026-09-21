// @vitest-environment jsdom
// web/src/Events.test.tsx — the Events browser tests (M3 Task 9). The
// './api' module is mocked wholesale (house rule: tests never touch the
// network); this file's tree imports getEvents (Events) and getRaw (the
// shared TraceDrawer), so those are the exports the mock carries.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Events from './Events'
import { getEvents, getRaw } from './api'
import type { EventRow, RawTrace } from './types'

vi.mock('./api', () => ({
  getEvents: vi.fn(),
  getRaw: vi.fn(),
}))

const mockGetEvents = vi.mocked(getEvents)
const mockGetRaw = vi.mocked(getRaw)

/** A parsed row for fp-acme-fw with both endpoints mapped. */
function eventRow(overrides: Partial<EventRow> = {}): EventRow {
  return {
    event_id: '3f2bd0a6-1b1e-4c5a-9d3e-a1b2c3d4e5f6',
    raw_id: '9a8b7c6d-5e4f-4a3b-8c2d-0e9f8a7b6c5d',
    fingerprint_id: 'fp-acme-fw',
    rule_version: 3,
    status: 'parsed',
    parsed_at: '2026-09-21T18:04:05Z',
    ocsf: {
      class_uid: 4001,
      class_name: 'Network Activity',
      activity_id: 0,
      severity_id: null,
      time: null,
      src_endpoint: { ip: '10.0.0.1', port: 445 },
      dst_endpoint: { ip: '10.0.0.2', port: 445 },
      action: 'DROP',
      message: null,
      metadata: { product: 'ULPF' },
      unmapped: {},
    },
    ...overrides,
  }
}

/** The raw line behind the parsed row (GET /api/events/{id}/raw shape). */
const rawTrace: RawTrace = {
  raw_id: '9a8b7c6d-5e4f-4a3b-8c2d-0e9f8a7b6c5d',
  received_at: '2026-09-21T18:04:04Z',
  source_id: 'acme-fw-01',
  transport: 'file',
  content_hash: 'sha256:abc123',
  raw_text: 'Sep 21 18:04:05 fw1 kernel: DROP tcp 10.0.0.1:445 -> 10.0.0.2:445',
}

/** One parsed + one unparsed row: the second exercises ocsf-null rendering
 * (— endpoints, — rule version). */
const twoRows: EventRow[] = [
  eventRow(),
  eventRow({
    event_id: 'c81d4d2e-7f6a-4b0c-9e5d-4f3e2d1c0b0a',
    raw_id: '01234567-89ab-4cde-8f01-234567890abc',
    fingerprint_id: 'fp-br-dns',
    rule_version: null,
    status: 'unparsed',
    parsed_at: '2026-09-21T18:04:07Z',
    ocsf: null,
  }),
]

afterEach(() => {
  cleanup() // vitest without globals does not auto-cleanup RTL renders
})

describe('Events browser', () => {
  it('renders rows from the current-view fetch: badges, mono fingerprints, rule v, src → dst', async () => {
    mockGetEvents.mockResolvedValue({ events: twoRows })
    const { container } = render(<Events />)

    // mount fetch: no status/fingerprint filter, default limit 50
    await screen.findByText('fp-acme-fw')
    expect(mockGetEvents).toHaveBeenCalledWith({
      status: undefined,
      fingerprint: undefined,
      limit: 50,
    })

    // both fingerprints render in mono cells
    expect(screen.getByText('fp-acme-fw').className).toBe('mono')
    expect(screen.getByText('fp-br-dns').className).toBe('mono')
    // status badges carry the badge-<status> classes
    expect(container.querySelector('.badge-parsed')).not.toBeNull()
    expect(container.querySelector('.badge-unparsed')).not.toBeNull()
    // parsed row: rule version + mapped endpoints; unparsed row: — / — → —
    expect(screen.getByText('3')).not.toBeNull()
    expect(screen.getByText('10.0.0.1 → 10.0.0.2')).not.toBeNull()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('— → —')).not.toBeNull()
    // topbar counts the current view
    expect(screen.getByText('2 event(s) in the current view')).not.toBeNull()
  })

  it('forwards filter changes to getEvents: status, fingerprint, limit', async () => {
    mockGetEvents.mockResolvedValue({ events: twoRows })
    render(<Events />)
    await screen.findByText('fp-acme-fw')

    fireEvent.change(screen.getByLabelText('status'), {
      target: { value: 'parsed' },
    })
    await waitFor(() => {
      expect(mockGetEvents).toHaveBeenLastCalledWith({
        status: 'parsed',
        fingerprint: undefined,
        limit: 50,
      })
    })

    fireEvent.change(screen.getByLabelText('fingerprint'), {
      target: { value: 'fp-acme-fw' },
    })
    await waitFor(() => {
      expect(mockGetEvents).toHaveBeenLastCalledWith({
        status: 'parsed',
        fingerprint: 'fp-acme-fw',
        limit: 50,
      })
    })

    fireEvent.change(screen.getByLabelText('limit'), {
      target: { value: '100' },
    })
    await waitFor(() => {
      expect(mockGetEvents).toHaveBeenLastCalledWith({
        status: 'parsed',
        fingerprint: 'fp-acme-fw',
        limit: 100,
      })
    })
  })

  it('clicking a row opens the TraceDrawer: getRaw by event id, raw line shown, Close clears', async () => {
    mockGetEvents.mockResolvedValue({ events: [eventRow()] })
    mockGetRaw.mockResolvedValue(rawTrace)
    render(<Events />)
    fireEvent.click(await screen.findByText('fp-acme-fw'))

    expect(mockGetRaw).toHaveBeenCalledWith(
      '3f2bd0a6-1b1e-4c5a-9d3e-a1b2c3d4e5f6',
      expect.anything(), // the AbortSignal the drawer cancels on close
    )
    expect(
      screen.getByRole('heading', { name: 'Traceability' }),
    ).not.toBeNull()
    // the raw line and the normalized document both render
    expect(
      await screen.findByText(
        'Sep 21 18:04:05 fw1 kernel: DROP tcp 10.0.0.1:445 -> 10.0.0.2:445',
      ),
    ).not.toBeNull()
    expect(screen.getByText(/"src_endpoint"/)).not.toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Close (Esc)' }))
    expect(
      screen.queryByRole('heading', { name: 'Traceability' }),
    ).toBeNull()
  })

  it('Enter on a row also opens the drawer (keyboard activation)', async () => {
    mockGetEvents.mockResolvedValue({ events: [eventRow()] })
    mockGetRaw.mockResolvedValue(rawTrace)
    render(<Events />)
    fireEvent.keyDown(await screen.findByText('fp-acme-fw'), { key: 'Enter' })

    expect(
      await screen.findByRole('heading', { name: 'Traceability' }),
    ).not.toBeNull()
  })

  it('shows the empty state when no events match', async () => {
    mockGetEvents.mockResolvedValue({ events: [] })
    render(<Events />)
    await screen.findByText(/no events match/i)
  })

  it('shows an error banner when the load fails, and Retry recovers', async () => {
    mockGetEvents.mockRejectedValueOnce(
      new Error('GET /api/events failed: 500 Internal Server Error'),
    )
    render(<Events />)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toMatch(/500/)

    mockGetEvents.mockResolvedValueOnce({ events: [eventRow()] })
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('fp-acme-fw')).not.toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
