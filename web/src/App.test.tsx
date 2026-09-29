// @vitest-environment jsdom
// web/src/App.test.tsx — the five-tab shell tests (M3 Task 10; spec §12's
// five pages: Overview, Review Queue, Events, Rules, Drift & Health). The
// './api' module is mocked wholesale (house rule: tests never touch the
// network) with empty-resolved fetchers for every page the tree can mount;
// EventSource is stubbed because the default Overview tab subscribes to the
// SSE stream and jsdom ships no EventSource.
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import {
  getDriftAlerts,
  getDriftMetrics,
  getEvents,
  getRules,
  getStats,
} from './api'
import type { Stats } from './types'

vi.mock('./api', () => ({
  getStats: vi.fn(),
  getEvents: vi.fn(),
  getRaw: vi.fn(),
  getRules: vi.fn(),
  getRuleHistory: vi.fn(),
  getAudit: vi.fn(),
  getDriftMetrics: vi.fn(),
  getDriftAlerts: vi.fn(),
  postJson: vi.fn(),
}))

const mockGetStats = vi.mocked(getStats)
const mockGetEvents = vi.mocked(getEvents)
const mockGetRules = vi.mocked(getRules)
const mockGetDriftMetrics = vi.mocked(getDriftMetrics)
const mockGetDriftAlerts = vi.mocked(getDriftAlerts)

/** Minimal EventSource double — the Overview tab only needs construction and
 * clean close on switch-away; no events are delivered in these tests. */
class FakeEventSource {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 2

  url: string
  readyState: number = FakeEventSource.OPEN
  onmessage: ((ev: MessageEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
  }

  close(): void {
    this.readyState = FakeEventSource.CLOSED
  }
}

const emptyStats: Stats = {
  raw_total: 0,
  by_status: { parsed: 0, unparsed: 0, parse_error: 0, quarantined: 0 },
  by_fingerprint: [],
  events_last_minute: 0,
  dlq_total: null,
}

beforeEach(() => {
  vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource)
  mockGetStats.mockResolvedValue(emptyStats)
  mockGetEvents.mockResolvedValue({ events: [] })
  mockGetRules.mockResolvedValue({ rules: [] })
  mockGetDriftMetrics.mockResolvedValue({ metrics: [] })
  mockGetDriftAlerts.mockResolvedValue({ alerts: [] })
})

afterEach(() => {
  cleanup() // vitest without globals does not auto-cleanup RTL renders
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('App shell — five tabs (spec §12)', () => {
  it('renders the five §12 tabs with Overview as the default page', () => {
    render(<App />)

    const tabs = screen.getAllByRole('tab')
    expect(tabs.map((t) => t.textContent)).toEqual([
      'Overview',
      'Review Queue',
      'Events',
      'Rules',
      'Drift & Health',
    ])
    // Overview mounts by default (its SSE feed + stats fetch fired)
    expect(
      screen.getByRole('heading', { name: 'ULPF Overview' }),
    ).not.toBeNull()
    expect(mockGetStats).toHaveBeenCalled()
    // …and none of the other pages is mounted
    expect(screen.queryByRole('heading', { name: 'Events' })).toBeNull()
    expect(screen.queryByRole('heading', { name: 'Rules' })).toBeNull()
  })

  it('switches to each of the other four pages, one at a time', async () => {
    render(<App />)

    fireEvent.click(screen.getByRole('tab', { name: 'Events' }))
    expect(
      await screen.findByRole('heading', { name: 'Events' }),
    ).not.toBeNull()
    expect(mockGetEvents).toHaveBeenCalledWith({
      status: undefined,
      fingerprint: undefined,
      limit: 50,
    })
    expect(
      screen.queryByRole('heading', { name: 'ULPF Overview' }),
    ).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: 'Review Queue' }))
    expect(
      await screen.findByRole('heading', { name: 'Review Queue' }),
    ).not.toBeNull()
    expect(mockGetRules).toHaveBeenCalledWith({ status: 'pending_review' })
    expect(screen.queryByRole('heading', { name: 'Events' })).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: 'Rules' }))
    expect(
      await screen.findByRole('heading', { name: 'Rules' }),
    ).not.toBeNull()
    expect(mockGetRules).toHaveBeenLastCalledWith()

    fireEvent.click(screen.getByRole('tab', { name: 'Drift & Health' }))
    expect(
      await screen.findByRole('heading', { name: 'Drift & Health' }),
    ).not.toBeNull()
    expect(mockGetDriftMetrics).toHaveBeenCalled()
    expect(mockGetDriftAlerts).toHaveBeenCalled()
    expect(screen.queryByRole('heading', { name: 'Rules' })).toBeNull()
  })

  it('marks exactly the active tab aria-selected', () => {
    render(<App />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs[0]?.getAttribute('aria-selected')).toBe('true')
    expect(tabs[4]?.getAttribute('aria-selected')).toBe('false')

    fireEvent.click(tabs[4])
    expect(tabs[4]?.getAttribute('aria-selected')).toBe('true')
    expect(tabs[0]?.getAttribute('aria-selected')).toBe('false')
    // the fifth page is Drift & Health
    expect(
      screen.getByRole('heading', { name: 'Drift & Health' }),
    ).not.toBeNull()
  })
})
