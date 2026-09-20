// @vitest-environment jsdom
// web/src/Rules.test.tsx — the Rules registry + audit trail page tests
// (Task 9). The './api' module is mocked (house rule: tests never touch the
// network); expanding a fingerprint mocks BOTH getRuleHistory and getAudit
// (the page fires both on expand — Task 9 ruling).
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Rules from './Rules'
import { getAudit, getRuleHistory, getRules, postJson } from './api'
import type { AuditRow, RuleRow } from './types'

vi.mock('./api', () => ({
  getRules: vi.fn(),
  getRuleHistory: vi.fn(),
  getAudit: vi.fn(),
  postJson: vi.fn(),
}))

const mockGetRules = vi.mocked(getRules)
const mockGetRuleHistory = vi.mocked(getRuleHistory)
const mockGetAudit = vi.mocked(getAudit)
const mockPostJson = vi.mocked(postJson)

/** An active v3 rule for fp-acme-fw — validation is null (the registry page
 * does not render the gate report; the Review Queue owns that). */
function ruleRow(overrides: Partial<RuleRow> = {}): RuleRow {
  return {
    id: 3,
    fingerprint_id: 'fp-acme-fw',
    version: 3,
    pattern: '^kernel: (?P<action>DROP|ACCEPT)\\s+.*src=(?P<src_ip>\\S+)',
    mappings: [{ source_field: 'src_ip', ocsf_path: 'src_endpoint.ip' }],
    provenance: 'slm',
    confidence: 0.87,
    status: 'active',
    created_by: 'onboarding',
    created_at: '2026-09-18T09:00:00Z',
    activated_at: '2026-09-19T10:00:00Z',
    deactivated_at: null,
    validation: null,
    ...overrides,
  }
}

/** The audit feed for fp-acme-fw, latest first (gateway ORDER BY id DESC):
 * three actions of the closed vocabulary, ts values distinct from the rule
 * rows' activated_at so assertions cannot collide across sections. */
const auditRows: AuditRow[] = [
  {
    id: 12,
    ts: '2026-09-19T10:00:05Z',
    actor: 'karthik',
    action: 'rule_approved',
    entity: 'fp-acme-fw',
    detail: { rule_id: 3, version: 3 },
  },
  {
    id: 9,
    ts: '2026-09-19T09:30:00Z',
    actor: 'slm-worker',
    action: 'candidate_created',
    entity: 'fp-acme-fw',
    detail: null,
  },
  {
    id: 4,
    ts: '2026-09-19T09:00:00Z',
    actor: 'slm-worker',
    action: 'samples_split',
    entity: 'fp-acme-fw',
    detail: { prompt: 5, held_out: 4 },
  },
]

afterEach(() => {
  cleanup() // vitest without globals does not auto-cleanup RTL renders
})

describe('Rules registry', () => {
  it('renders one summary row per fingerprint (latest version) from the all-statuses fetch', async () => {
    mockGetRules.mockResolvedValue({
      rules: [
        ruleRow(), // v3 active — the latest for fp-acme-fw
        ruleRow({ id: 2, version: 2, status: 'superseded', activated_at: null }),
        ruleRow({
          id: 7,
          fingerprint_id: 'fp-br-dns',
          version: 1,
          provenance: 'human',
          status: 'pending_review',
          activated_at: null,
        }),
      ],
    })
    render(<Rules />)
    await screen.findByText('fp-acme-fw')

    // the registry fetch has NO status filter — every status shows up
    expect(mockGetRules).toHaveBeenCalledWith()
    // both fingerprints listed (grouped: 3 rule rows -> 2 summary rows)…
    expect(screen.getByText('fp-br-dns')).not.toBeNull()
    // …and each row shows the LATEST version only
    expect(screen.getByText('v3')).not.toBeNull()
    expect(screen.queryByText('v2')).toBeNull()
    // the superseded older version's status is not the row's badge…
    expect(screen.queryByText('superseded')).toBeNull()
    // …and the topbar counts fingerprints, not rule rows
    expect(screen.getByText('2 fingerprint(s) registered')).not.toBeNull()
  })

  it('expanding a fingerprint loads the version timeline: version, status badge, provenance, activated_at', async () => {
    mockGetRules.mockResolvedValue({ rules: [ruleRow()] })
    mockGetRuleHistory.mockResolvedValue({
      rules: [
        ruleRow(),
        ruleRow({
          id: 2,
          version: 2,
          status: 'superseded',
          provenance: 'slm-edited',
          activated_at: '2026-09-18T08:00:00Z',
        }),
      ],
      audit: [],
    })
    mockGetAudit.mockResolvedValue({ audit: [] })
    render(<Rules />)
    fireEvent.click(await screen.findByText('fp-acme-fw'))

    expect(mockGetRuleHistory).toHaveBeenCalledWith('fp-acme-fw')
    // the older version appears in the timeline with its own status badge,
    // provenance and activation timestamp
    expect(await screen.findByText('superseded')).not.toBeNull()
    expect(screen.getByText('v2')).not.toBeNull()
    expect(screen.getByText('slm-edited')).not.toBeNull()
    expect(screen.getByText('2026-09-18T08:00:00Z')).not.toBeNull()
    // the latest version's badge shows in summary AND timeline
    expect(screen.getAllByText('active').length).toBeGreaterThanOrEqual(2)
  })

  it('expanding a fingerprint ALSO loads the audit feed and renders ts · actor · action verbatim', async () => {
    mockGetRules.mockResolvedValue({ rules: [ruleRow()] })
    // the history response embeds a decoy audit array that must go UNUSED:
    // the feed comes from getAudit (Task 9 ruling)
    mockGetRuleHistory.mockResolvedValue({
      rules: [ruleRow()],
      audit: [
        {
          id: 99,
          ts: '2026-01-01T00:00:00Z',
          actor: 'decoy',
          action: 'rule_rejected',
          entity: 'fp-acme-fw',
          detail: null,
        },
      ],
    })
    mockGetAudit.mockResolvedValue({ audit: auditRows })
    render(<Rules />)
    fireEvent.click(await screen.findByText('fp-acme-fw'))

    expect(mockGetAudit).toHaveBeenCalledWith('fp-acme-fw')
    // action strings are the closed vocabulary, rendered VERBATIM
    expect(await screen.findByText('rule_approved')).not.toBeNull()
    expect(screen.getByText('candidate_created')).not.toBeNull()
    expect(screen.getByText('samples_split')).not.toBeNull()
    // ts · actor lines
    expect(screen.getByText('2026-09-19T10:00:05Z')).not.toBeNull()
    expect(screen.getByText('karthik')).not.toBeNull()
    expect(screen.getAllByText('slm-worker')).toHaveLength(2)
    // the decoy from getRuleHistory's embedded audit array never renders
    expect(screen.queryByText('rule_rejected')).toBeNull()
    expect(screen.queryByText('decoy')).toBeNull()
  })

  it('Deactivate POSTs {actor: anonymous} and the row badge flips after the refresh', async () => {
    mockGetRules.mockResolvedValueOnce({ rules: [ruleRow()] }) // mount
    mockGetRules.mockResolvedValueOnce({
      // post-deactivate refresh: same fp, badge flipped
      rules: [ruleRow({ status: 'deactivated', deactivated_at: '2026-09-19T11:00:00Z' })],
    })
    mockPostJson.mockResolvedValueOnce({ rule_id: 3, version: 3, status: 'deactivated' })
    render(<Rules />)
    await screen.findByText('fp-acme-fw')

    fireEvent.click(screen.getByRole('button', { name: 'Deactivate' }))
    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/deactivate',
        { actor: 'anonymous' },
      )
    })
    // the list was refetched: the badge reads deactivated and the button is
    // gone (nothing active left to deactivate)
    await screen.findByText('deactivated')
    expect(screen.queryByRole('button', { name: 'Deactivate' })).toBeNull()
    expect(mockGetRules).toHaveBeenCalledTimes(2)
  })

  it('shows an error banner when the registry load fails, and Retry recovers', async () => {
    mockGetRules.mockRejectedValue(
      new Error('GET /api/rules failed: 500 Internal Server Error'),
    )
    render(<Rules />)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toMatch(/500/)

    mockGetRules.mockResolvedValueOnce({ rules: [] })
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await screen.findByText(/no rules yet/i)
  })

  it('shows an error banner when the expand fetch fails, without wiping the registry rows', async () => {
    mockGetRules.mockResolvedValue({ rules: [ruleRow()] })
    mockGetRuleHistory.mockRejectedValue(
      new Error('GET /api/rules/fp-acme-fw failed: 500 Internal Server Error'),
    )
    mockGetAudit.mockResolvedValue({ audit: [] })
    render(<Rules />)
    fireEvent.click(await screen.findByText('fp-acme-fw'))

    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toMatch(/500/)
    // a failed expand must not wipe the row — the reviewer can collapse and
    // re-expand to retry
    expect(screen.getByText('fp-acme-fw')).not.toBeNull()
  })

  it('shows the empty state when no rules are registered', async () => {
    mockGetRules.mockResolvedValue({ rules: [] })
    render(<Rules />)
    await screen.findByText(/no rules yet/i)
  })
})
