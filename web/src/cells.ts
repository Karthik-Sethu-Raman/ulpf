// web/src/cells.ts — tiny pure cell formatters shared by more than one page
// (Overview in App.tsx, the Events browser). Kept here rather than copy-pasted
// per page so the fifth §12 page can reuse them too.
import type { OcsfEndpoint } from './types'

export function endpointIp(ep: OcsfEndpoint | null): string {
  return ep?.ip ?? '—'
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString()
}
