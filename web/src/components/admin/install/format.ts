/** Formats a byte count with binary units (1 KiB = 1024 B). */
export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  if (i === 0) return `${n} B`
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i] ?? ''}`
}

/** Formats a duration in milliseconds as the two largest units, e.g. "3 d 4 h" or "12 min 5 s". */
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const s = Math.floor(ms / 1000)
  const parts: [number, string][] = [
    [Math.floor(s / 86400), 'd'],
    [Math.floor((s % 86400) / 3600), 'h'],
    [Math.floor((s % 3600) / 60), 'min'],
    [s % 60, 's'],
  ]
  const first = parts.findIndex(([v]) => v > 0)
  if (first === -1) return '0 s'
  return parts
    .slice(first, first + 2)
    .filter(([v], i) => i === 0 || v > 0)
    .map(([v, u]) => `${v} ${u}`)
    .join(' ')
}

/** Converts a `datetime-local` input value (local time, no zone) to an ISO 8601 UTC timestamp, or '' if empty/invalid. */
export function localInputToIso(value: string): string {
  if (!value) return ''
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? '' : d.toISOString()
}

/** Formats an ISO timestamp in the viewer's locale ('—' when absent). */
export function formatDateTime(iso: string | undefined | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

/** "name" when known, otherwise "type:id" (or just the type for system actors). */
export function actorLabel(e: { actor_type: string; actor_id?: string; actor_name?: string }): string {
  if (e.actor_name) return e.actor_name
  return e.actor_id ? `${e.actor_type}:${e.actor_id}` : e.actor_type
}

/** "type:id" for an audit target ('—' when the event has none). */
export function targetLabel(e: { target_type?: string; target_id?: string }): string {
  if (!e.target_type && !e.target_id) return '—'
  if (!e.target_id) return e.target_type ?? '—'
  return e.target_type ? `${e.target_type}:${e.target_id}` : e.target_id
}

/** Pretty-prints audit details as JSON text (rendered as text, never as HTML). */
export function detailsJson(details: Record<string, unknown> | undefined): string {
  if (!details || Object.keys(details).length === 0) return '{}'
  return JSON.stringify(details, null, 2)
}
