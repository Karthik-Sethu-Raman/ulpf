// @vitest-environment jsdom
// web/src/ReviewQueue.test.tsx — the Review Queue + three-tab shell tests
// (Task 8). The './api' module is mocked (house rule: tests never touch the
// network); the shell test additionally stubs EventSource, which jsdom does
// not ship, because Overview mounts the SSE hook.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import ReviewQueue from './ReviewQueue'
import { getRules, postJson } from './api'
import type { RuleRow, ValidationReport } from './types'

vi.mock('./api', () => ({
  getStats: vi.fn().mockResolvedValue(null),
  getEvents: vi.fn(),
  getRaw: vi.fn().mockResolvedValue(null),
  getRules: vi.fn(),
  getSamples: vi.fn(),
  postJson: vi.fn(),
}))

const mockGetRules = vi.mocked(getRules)
const mockPostJson = vi.mocked(postJson)

/** Minimal EventSource double: jsdom has none, and the Overview feed only
 * needs the constructor + close() to exist. */
class StubEventSource {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 2
  readyState = StubEventSource.OPEN
  onmessage: ((ev: MessageEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  close(): void {
    this.readyState = StubEventSource.CLOSED
  }
}

/** A pending_review candidate whose report has one failing check, a note, and
 * one parsed preview — exercises the ✓/✗ grid and the preview pair. */
function pendingRule(overrides: Partial<RuleRow> = {}): RuleRow {
  const validation: ValidationReport = {
    passed: false,
    checks: {
      caps_and_allowlist: true,
      samples_parse: true,
      held_out_match_all: true,
      ip_fields_valid: true,
      port_fields_valid: true,
      no_orphan_mappings: false,
      adversarial_probe: true,
      no_hardcoded_literals: true,
    },
    held_out_match_rate: 0.75,
    notes: ['held-out line 3: boom'],
    previews: [
      {
        line: 'Sep 19 09:05:11 fw1 kernel: DROP tcp 10.0.0.1:445 -> 10.0.0.2:445',
        status: 'parsed',
        ocsf: {
          class_uid: 4001,
          src_endpoint: { ip: '10.0.0.1', port: 445 },
          dst_endpoint: { ip: '10.0.0.2', port: 445 },
        },
      },
    ],
    prompt_count: 5,
    held_out_count: 4,
  }
  return {
    id: 42,
    fingerprint_id: 'fp-acme-fw',
    version: 3,
    pattern: '^kernel: (?P<action>DROP|ACCEPT)\\s+.*src=(?P<src_ip>\\S+)',
    mappings: [
      { source_field: 'src_ip', ocsf_path: 'src_endpoint.ip' },
      { source_field: 'action', ocsf_path: 'action' },
    ],
    provenance: 'slm',
    confidence: 0.87,
    status: 'pending_review',
    created_by: 'onboarding',
    created_at: '2026-09-19T09:05:00Z',
    activated_at: null,
    deactivated_at: null,
    validation,
    ...overrides,
  }
}

beforeEach(() => {
  vi.stubGlobal('EventSource', StubEventSource as unknown as typeof EventSource)
})

afterEach(() => {
  cleanup() // vitest without globals does not auto-cleanup RTL renders
  vi.unstubAllGlobals()
})

describe('ReviewQueue', () => {
  it('renders a pending candidate: fingerprint, provenance, confidence, ✓/✗ checks grid', async () => {
    mockGetRules.mockResolvedValue({ rules: [pendingRule()] })
    render(<ReviewQueue />)
    // mount fetch is scoped to pending_review
    await screen.findByText('fp-acme-fw')
    expect(mockGetRules).toHaveBeenCalledWith({ status: 'pending_review' })
    expect(screen.getByText('slm')).not.toBeNull()
    // T5-f: the honest number is held_out_match_rate, surfaced next to the
    // optimistic prompt-only confidence
    expect(screen.getByText('0.87')).not.toBeNull()
    expect(screen.getByText('75%')).not.toBeNull()
    // checks grid: verbatim key names, one ✓ per passing check, ✗ for the
    // single failing one
    expect(screen.getByText('caps_and_allowlist')).not.toBeNull()
    expect(screen.getByText('no_orphan_mappings')).not.toBeNull()
    expect(screen.getAllByText('✓')).toHaveLength(7)
    expect(screen.getAllByText('✗')).toHaveLength(1)
    // the report's notes are visible
    expect(screen.getByText(/held-out line 3: boom/)).not.toBeNull()
  })

  it('renders a before/after preview pair: held-out line then pretty-printed OCSF', async () => {
    mockGetRules.mockResolvedValue({ rules: [pendingRule()] })
    render(<ReviewQueue />)
    await screen.findByText(
      'Sep 19 09:05:11 fw1 kernel: DROP tcp 10.0.0.1:445 -> 10.0.0.2:445',
    )
    expect(screen.getByText(/"src_endpoint"/)).not.toBeNull()
    expect(screen.getByText(/"dst_endpoint"/)).not.toBeNull()
  })

  it('Approve POSTs {actor, reason} from the inputs to the candidate URL, then refreshes', async () => {
    const rule = pendingRule()
    mockGetRules.mockResolvedValueOnce({ rules: [rule] }) // mount
    mockGetRules.mockResolvedValueOnce({ rules: [] }) // post-approve refresh
    mockPostJson.mockResolvedValueOnce({ rule_id: 42, version: 3, status: 'active' })
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')

    fireEvent.change(screen.getByLabelText('actor'), {
      target: { value: 'karthik' },
    })
    fireEvent.change(screen.getByLabelText('reason'), {
      target: { value: 'matches the ACME DROP format' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))

    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/candidates/42/approve',
        { actor: 'karthik', reason: 'matches the ACME DROP format' },
      )
    })
    // the list is refetched after the action; the approved card is gone
    await screen.findByText(/no pending candidates/i)
    expect(mockGetRules).toHaveBeenCalledTimes(2)
  })

  it('Approve defaults the actor to anonymous when the input is untouched', async () => {
    mockGetRules.mockResolvedValueOnce({ rules: [pendingRule()] })
    mockGetRules.mockResolvedValueOnce({ rules: [] })
    mockPostJson.mockResolvedValueOnce({ rule_id: 42, version: 3, status: 'active' })
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/candidates/42/approve',
        { actor: 'anonymous' },
      )
    })
  })

  it('shows an error banner when the approve POST fails (non-2xx)', async () => {
    mockGetRules.mockResolvedValue({ rules: [pendingRule()] })
    mockPostJson.mockRejectedValueOnce(
      new Error(
        'POST /api/rules/fp-acme-fw/candidates/42/approve failed: 409 Conflict',
      ),
    )
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toMatch(/409/)
    // a failed action must not wipe the card — the reviewer can retry
    expect(screen.getByText('fp-acme-fw')).not.toBeNull()
  })

  it('mapping editor edits a row and approve sends edited_mappings', async () => {
    mockGetRules.mockResolvedValueOnce({ rules: [pendingRule()] })
    mockGetRules.mockResolvedValueOnce({ rules: [] })
    mockPostJson.mockResolvedValueOnce({ rule_id: 43, version: 4, status: 'active' })
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')

    fireEvent.change(screen.getByLabelText('source_field row 1'), {
      target: { value: 'src_addr' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))

    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/candidates/42/approve',
        {
          actor: 'anonymous',
          edited_mappings: [
            { source_field: 'src_addr', ocsf_path: 'src_endpoint.ip' },
            { source_field: 'action', ocsf_path: 'action' },
          ],
        },
      )
    })
  })

  it('mapping editor adds and removes rows before approve', async () => {
    mockGetRules.mockResolvedValueOnce({ rules: [pendingRule()] })
    mockGetRules.mockResolvedValueOnce({ rules: [] })
    mockPostJson.mockResolvedValueOnce({ rule_id: 43, version: 4, status: 'active' })
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')

    fireEvent.click(screen.getByRole('button', { name: 'Add mapping' }))
    fireEvent.change(screen.getByLabelText('source_field row 3'), {
      target: { value: 'msg' },
    })
    fireEvent.change(screen.getByLabelText('ocsf_path row 3'), {
      target: { value: 'message' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Remove row 2' }))
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))

    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/candidates/42/approve',
        {
          actor: 'anonymous',
          edited_mappings: [
            { source_field: 'src_ip', ocsf_path: 'src_endpoint.ip' },
            { source_field: 'msg', ocsf_path: 'message' },
          ],
        },
      )
    })
  })

  it('override textarea populated -> approve sends override {pattern, mappings}', async () => {
    mockGetRules.mockResolvedValueOnce({ rules: [pendingRule()] })
    mockGetRules.mockResolvedValueOnce({ rules: [] })
    mockPostJson.mockResolvedValueOnce({ rule_id: 44, version: 4, status: 'active' })
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')

    fireEvent.click(screen.getByRole('button', { name: /override/i }))
    fireEvent.change(screen.getByLabelText('override pattern'), {
      target: { value: '^hand-written: (?P<src_ip>\\S+)' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))

    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/candidates/42/approve',
        {
          actor: 'anonymous',
          override: {
            pattern: '^hand-written: (?P<src_ip>\\S+)',
            mappings: [
              { source_field: 'src_ip', ocsf_path: 'src_endpoint.ip' },
              { source_field: 'action', ocsf_path: 'action' },
            ],
          },
        },
      )
    })
  })

  it('Reject POSTs {actor} and the card disappears after the refresh', async () => {
    mockGetRules.mockResolvedValueOnce({ rules: [pendingRule()] })
    mockGetRules.mockResolvedValueOnce({ rules: [] })
    mockPostJson.mockResolvedValueOnce({ status: 'rejected' })
    render(<ReviewQueue />)
    await screen.findByText('fp-acme-fw')

    fireEvent.change(screen.getByLabelText('actor'), {
      target: { value: 'reviewer1' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }))

    await waitFor(() => {
      expect(mockPostJson).toHaveBeenCalledWith(
        '/api/rules/fp-acme-fw/candidates/42/reject',
        { actor: 'reviewer1' },
      )
    })
    await screen.findByText(/no pending candidates/i)
    expect(screen.queryByText('fp-acme-fw')).toBeNull()
  })

  it('shows the empty state when no candidates are pending', async () => {
    mockGetRules.mockResolvedValue({ rules: [] })
    render(<ReviewQueue />)
    await screen.findByText(/no pending candidates/i)
  })

  it('shows an error banner when the initial load fails', async () => {
    mockGetRules.mockRejectedValue(
      new Error('GET /api/rules failed: 500 Server Error'),
    )
    render(<ReviewQueue />)
    await screen.findByRole('alert')
    expect(screen.getByRole('alert').textContent).toMatch(/500/)
  })
})

describe('three-tab shell', () => {
  it('switches between Overview, Review Queue, and the Rules placeholder', async () => {
    mockGetRules.mockResolvedValue({ rules: [pendingRule()] })
    render(<App />)

    // Overview is the landing tab: the live-feed page heading
    expect(screen.getByRole('heading', { name: 'ULPF Overview' })).not.toBeNull()
    expect(screen.queryByText('fp-acme-fw')).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: 'Review Queue' }))
    expect(await screen.findByText('fp-acme-fw')).not.toBeNull()
    expect(
      screen.queryByRole('heading', { name: 'ULPF Overview' }),
    ).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: 'Rules' }))
    expect(
      await screen.findByText(/rules management arrives in task 9/i),
    ).not.toBeNull()
    expect(screen.queryByText('fp-acme-fw')).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: 'Overview' }))
    expect(screen.getByRole('heading', { name: 'ULPF Overview' })).not.toBeNull()
  })
})
