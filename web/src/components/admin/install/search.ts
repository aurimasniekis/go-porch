/** Search params accepted by the audit pages (links from other pages pre-fill the filters). */
export interface AuditSearch {
  actor?: string
  target?: string
  action?: string
  tenant?: string
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' && v.length <= 64 ? v : undefined
}

export function auditSearch(s: Record<string, unknown>): AuditSearch {
  const out: AuditSearch = {}
  const actor = str(s.actor)
  const target = str(s.target)
  const action = str(s.action)
  const tenant = str(s.tenant)
  if (actor) out.actor = actor
  if (target) out.target = target
  if (action) out.action = action
  if (tenant) out.tenant = tenant
  return out
}

/** Search params of the sessions page. */
export interface SessionsSearch {
  user?: string
}

export function sessionsSearch(s: Record<string, unknown>): SessionsSearch {
  const user = str(s.user)
  return user ? { user } : {}
}
