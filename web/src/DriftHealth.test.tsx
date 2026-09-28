// @vitest-environment jsdom
// web/src/DriftHealth.test.tsx — the Drift & Health page tests (M3 Task 10,
// the fifth §12 page). The './api' module is mocked wholesale (house rule:
// tests never touch the network); this file's tree imports getDriftMetrics,
// getDriftAlerts (the page) and postJson (the un-quarantine button).
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import DriftHealth from './DriftHealth'
import { getDriftAlerts, getDriftMetrics, postJson } from './api'
import type {
  AuditRow,
  DriftAlertRow,
  DriftMetricRow,
  UnquarantineResponse,
} from './types'

vi.mock('./api', () => ({
  getDriftMetrics: vi.fn(),
  getDriftAlerts: vi.fn(),
  postJson: vi.fn(),
}))

const mockGetDriftMetrics = vi.mocked(getDriftMetrics)
const mockGetDriftAlerts = vi.mocked(getDriftAlerts)
const mockPostJson = vi.mocked(postJson)

/** A severe window row for fp-acme-fw / src_endpoint.ip — the firmware-drift
 * demo shape: violation rate through the tier-1 ladder, ipv4-dominant. */
function metricRow(overrides: Partial<DriftMetricRow> = {}): DriftMetricRow {
  return {
    fingerprint_id: 'fp-acme-fw',
    rule_version: 3,
    field: 'src_endpoint.ip',
    window_start: '2026-09-22T10:00:00Z',
    window_end: '2026-09-22T10:05:00Z',
    events_count: 240,
    null_rate: 0.42,
    match_rate: null,
    violation_rate: 0.61,
    shape_dist: { ipv4: 90, int: 10 },
    severity: 'severe',
    action_taken: 'rule_deactivated',
    ...overrides,
  }
}

/** A window-kind alert row (the row IS the alert). */
function windowAlert(overrides: Partial<DriftMetricRow> = {}): DriftAlertRow {
  return { ...metricRow(overrides), kind: 'window' }
}

/** An audit-kind alert row from the enforcement vocabulary. */
function auditAlert(overrides: Partial<AuditRow> = {}): DriftAlertRow {
  return {
    id: 41,
    ts: '2026-09-22T10:06:00Z',
    actor: 'drift',
    action: 'field_quarantined',
    entity: 'fp-acme-fw',
    detail: { field: 'dst_endpoint.ip', rule_id: 3, version: 3 },
    kind: 'audit',
    ...overrides,
  }
}

/** POST /api/rules/{fp}/unquarantine 200 response shape. */
const unquarantineOk: UnquarantineResponse = {
  fingerprint_id: 'fp-acme-fw',
  field: 'dst_endpoint.ip',
  quarantined_fields: [],
}

afterEach(() => {
  cleanup() // vitest without globals does not auto-cleanup RTL renders
  vi.clearAllMocks()
})

describe('Drift & Health — Field health', () => {
  it('renders one row per (fp, field) metric: severity badge, rates, shape top class, action, topbar counts', async () => {
    mockGetDriftMetrics.mockResolvedValue({
      metrics: [
        metricRow(),
        metricRow({
          field: 'dst_endpoint.ip',
          window_start: '2026-09-22T09:55:00Z',
          window_end: '2026-09-22T10:00:00Z',
          null_rate: 0,
          violation_rate: 0.05,
          shape_dist: {}, // empty histogram — shape top renders '—'
          severity: 'moderate',
          action_taken: 'field_quarantined',
        }),
      ],
    })
    mockGetDriftAlerts.mockResolvedValue({ alerts: [] })
    const { container } = render(<DriftHealth />)

    // both feeds load on mount
    await screen.findAllByText('fp-acme-fw') // one cell per row (same fp)
    expect(mockGetDriftMetrics).toHaveBeenCalledWith()
    expect(mockGetDriftAlerts).toHaveBeenCalledWith()

    // identity cells are mono; severity badges carry badge-<severity>
    expect(screen.getAllByText('fp-acme-fw').length).toBeGreaterThanOrEqual(2)
    expect(container.querySelector('.badge-severe')).not.toBeNull()
    expect(container.querySelector('.badge-moderate')).not.toBeNull()
    // rates render as rounded percentages ('—' where the window measures none)
    expect(screen.getByText('42%')).not.toBeNull() // null_rate
    expect(screen.getByText('61%')).not.toBeNull() // violation_rate
    expect(screen.getByText('0%')).not.toBeNull() // second row null_rate
    // shape top class = argmax of shape_dist; '—' when the histogram is empty
    // (also '—' for the null match_rate — __rule__-only measurement)
    expect(screen.getByText('ipv4')).not.toBeNull()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2)
    // action strings render verbatim (the string IS the label)
    expect(screen.getByText('rule_deactivated')).not.toBeNull()
    expect(screen.getByText('field_quarantined')).not.toBeNull()
    // events count rides each row (both fixtures carry 240)
    expect(screen.getAllByText('240')).toHaveLength(2)
    // topbar counts both feeds
    expect(
      screen.getByText('2 field signal(s) · 0 alert(s)'),
    ).not.toBeNull()
  })

  it('renders __rule__ sentinel rows with their match_rate', async () => {
    mockGetDriftMetrics.mockResolvedValue({
      metrics: [
        metricRow({
          field: '__rule__',
          null_rate: null,
          match_rate: 0.93,
          violation_rate: null,
          shape_dist: null,
          severity: 'minor',
          action_taken: 'alert',
        }),
      ],
    })
    mockGetDriftAlerts.mockResolvedValue({ alerts: [] })
    render(<DriftHealth />)
    await screen.findByText('__rule__')

    expect(screen.getByText('93%')).not.toBeNull()
    // null_rate / violation_rate / shape_dist are all null on a sentinel row
    expect(screen.getAllByText('—')).toHaveLength(3)
  })

  it('shows the empty states when no windows have closed and no alerts exist', async () => {
    mockGetDriftMetrics.mockResolvedValue({ metrics: [] })
    mockGetDriftAlerts.mockResolvedValue({ alerts: [] })
    render(<DriftHealth />)
    await screen.findByText(/no closed drift windows yet/i)
    expect(screen.getByText(/no drift alerts/i)).not.toBeNull()
    expect(screen.getByText(/no unmapped telemetry keys observed/i)).not.toBeNull()
  })
})

describe('Drift & Health — Enforcement feed', () => {
  it('renders the ONE merged feed in endpoint order, discriminated by kind (no client re-sort)', async () => {
    // Deliberately NOT time-sorted: the endpoint's latest-first order is the
    // contract (P-4) and the page must render the array verbatim — a client
    // re-sort would reorder these rows.
    mockGetDriftMetrics.mockResolvedValue({ metrics: [metricRow()] })
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [
        windowAlert({ window_start: '2026-09-22T10:00:00Z', severity: 'severe' }),
        auditAlert({
          id: 44,
          ts: '2026-09-22T10:30:00Z',
          actor: 'karthik',
          action: 'field_unquarantined',
          detail: { field: 'src_endpoint.ip', rule_id: 3, version: 3, reason: 'fixed' },
        }),
        windowAlert({
          field: 'dst_endpoint.ip',
          window_start: '2026-09-22T09:00:00Z',
          severity: 'minor',
          action_taken: 'alert',
          shape_dist: {},
        }),
        auditAlert({
          id: 40,
          ts: '2026-09-22T09:10:00Z',
          action: 'rule_deactivated',
          detail: { rule_id: 3, version: 3, window_start: '2026-09-22T09:00:00Z' },
        }),
      ],
    })
    const { container } = render(<DriftHealth />)
    await screen.findByText(/alert\(s\)/)

    const items = container.querySelectorAll('.drift-feed li')
    expect(items).toHaveLength(4)
    // item order is the endpoint's array order, verbatim
    expect(items[0]?.textContent).toContain('fp-acme-fw')
    expect(items[0]?.textContent).toContain('src_endpoint.ip')
    expect(items[0]?.textContent).toContain('severe')
    // window rows carry no actor — the audit rows do
    expect(items[0]?.textContent).not.toContain('karthik')
    expect(items[1]?.textContent).toContain('karthik')
    expect(items[1]?.textContent).toContain('field_unquarantined')
    expect(items[1]?.textContent).toContain('src_endpoint.ip')
    expect(items[2]?.textContent).toContain('dst_endpoint.ip')
    expect(items[2]?.textContent).toContain('minor')
    expect(items[2]?.textContent).toContain('alert')
    // rule_deactivated audit rows have no field in detail — '—'
    expect(items[3]?.textContent).toContain('drift')
    expect(items[3]?.textContent).toContain('rule_deactivated')
    expect(items[3]?.textContent).toContain('—')
    // topbar counts the merged feed
    expect(
      screen.getByText('1 field signal(s) · 4 alert(s)'),
    ).not.toBeNull()
  })
})

describe('Drift & Health — Un-quarantine', () => {
  it('shows the button only on currently-quarantined fields (latest audit transition wins), POSTs {field, actor:"ui"} and refetches both feeds', async () => {
    const metrics = [
      metricRow({ field: 'src_endpoint.ip' }),
      metricRow({ field: 'dst_endpoint.ip' }),
    ]
    // Latest-first: src was un-quarantined AFTER its quarantine (not
    // quarantined anymore); dst's latest transition is the quarantine.
    const initialAlerts: DriftAlertRow[] = [
      auditAlert({
        id: 46,
        ts: '2026-09-22T11:00:00Z',
        actor: 'karthik',
        action: 'field_unquarantined',
        detail: { field: 'src_endpoint.ip', rule_id: 3, version: 3 },
      }),
      auditAlert({
        id: 45,
        ts: '2026-09-22T10:30:00Z',
        action: 'field_quarantined',
        detail: { field: 'dst_endpoint.ip', rule_id: 3, version: 3 },
      }),
      auditAlert({
        id: 44,
        ts: '2026-09-22T10:00:00Z',
        action: 'field_quarantined',
        detail: { field: 'src_endpoint.ip', rule_id: 3, version: 3 },
      }),
    ]
    mockGetDriftMetrics.mockResolvedValue({ metrics })
    mockGetDriftAlerts.mockResolvedValueOnce({ alerts: initialAlerts })
    // post-click refetch: the latest dst transition is now the un-quarantine
    mockGetDriftAlerts.mockResolvedValueOnce({
      alerts: [
        auditAlert({
          id: 47,
          ts: '2026-09-22T11:05:00Z',
          actor: 'ui',
          action: 'field_unquarantined',
          detail: { field: 'dst_endpoint.ip', rule_id: 3, version: 3 },
        }),
        ...initialAlerts,
      ],
    })
    mockPostJson.mockResolvedValueOnce(unquarantineOk)
    render(<DriftHealth />)
    // the field shows in its table row AND the enforcement feed
    await screen.findAllByText('dst_endpoint.ip')

    // exactly one button — on the dst row, not the src row
    const buttons = screen.getAllByRole('button', { name: 'Un-quarantine' })
    expect(buttons).toHaveLength(1)
    expect(buttons[0]?.closest('tr')?.textContent).toContain('dst_endpoint.ip')

    fireEvent.click(buttons[0])
    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/unquarantine',
        { field: 'dst_endpoint.ip', actor: 'ui' },
      )
    })
    // both feeds were refetched and the button left with the new fold
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'Un-quarantine' })).toBeNull()
    })
    expect(mockGetDriftMetrics).toHaveBeenCalledTimes(2)
    expect(mockGetDriftAlerts).toHaveBeenCalledTimes(2)
  })

  it('shows a row-level error banner when the POST fails (409: not quarantined)', async () => {
    mockGetDriftMetrics.mockResolvedValue({
      metrics: [metricRow({ field: 'dst_endpoint.ip' })],
    })
    mockGetDriftAlerts.mockResolvedValue({
      alerts: [
        auditAlert({
          action: 'field_quarantined',
          detail: { field: 'dst_endpoint.ip', rule_id: 3, version: 3 },
        }),
      ],
    })
    mockPostJson.mockRejectedValueOnce(
      new Error(
        'POST /api/rules/fp-acme-fw/unquarantine failed: field ' +
          "'dst_endpoint.ip' is not quarantined on the active rule",
      ),
    )
    render(<DriftHealth />)
    fireEvent.click(await screen.findByRole('button', { name: 'Un-quarantine' }))

    const banner = await screen.findByRole('alert')
    expect(banner.textContent).toMatch(/un-quarantine failed/)
    expect(banner.textContent).toMatch(/not quarantined/)
  })
})

describe('Drift & Health — Extension opportunities', () => {
  it('renders one distinct card per unmapped.* metric row, titled "new telemetry key observed"', async () => {
    mockGetDriftMetrics.mockResolvedValue({
      metrics: [
        metricRow({
          field: 'unmapped.SRCADDR',
          null_rate: 0.98,
          violation_rate: null,
          shape_dist: { free_text: 5 },
          severity: 'minor',
          action_taken: 'alert',
          events_count: 50,
        }),
        metricRow({
          field: 'unmapped.fw_build',
          null_rate: 0,
          violation_rate: null,
          shape_dist: {},
          severity: 'none',
          action_taken: null,
          events_count: 50,
        }),
        metricRow(), // a mapped field — no card
      ],
    })
    mockGetDriftAlerts.mockResolvedValue({ alerts: [] })
    render(<DriftHealth />)
    // the key shows in its table row AND its opportunity card
    await screen.findAllByText('unmapped.SRCADDR')

    const titles = screen.getAllByText('new telemetry key observed')
    expect(titles).toHaveLength(2)
    // each unmapped key shows in its table row AND its card
    expect(screen.getAllByText('unmapped.fw_build')).toHaveLength(2)
    // the mapped field stays in the field-health table but gets no card copy
    expect(screen.getAllByText('src_endpoint.ip').length).toBe(1)
  })
})

describe('Drift & Health — load failure', () => {
  it('shows an error banner when the feeds fail, and Retry recovers', async () => {
    mockGetDriftMetrics.mockRejectedValueOnce(
      new Error('GET /api/drift/metrics failed: 500 Internal Server Error'),
    )
    mockGetDriftAlerts.mockResolvedValue({ alerts: [] })
    render(<DriftHealth />)
    const banner = await screen.findByRole('alert')
    expect(banner.textContent).toMatch(/drift data unavailable/)
    expect(banner.textContent).toMatch(/500/)

    mockGetDriftMetrics.mockResolvedValueOnce({ metrics: [metricRow()] })
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('fp-acme-fw')).not.toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
