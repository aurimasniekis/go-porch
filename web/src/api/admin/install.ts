import { infiniteQueryOptions, queryOptions } from '@tanstack/react-query'
import { api, ApiError, unwrap, type Schemas } from '@/api/client'

/** undefined for an empty or missing string (empty cursors and filters are omitted from queries). */
function nonEmpty(s: string | undefined): string | undefined {
  return s === '' ? undefined : s
}

export type SystemHealth = Schemas['SystemHealth']
export type AuditEvent = Schemas['AuditEvent']
export type AuditPage = Schemas['AuditPage']
export type AdminSession = Schemas['AdminSession']
export type Alert = Schemas['Alert']
export type SigningKey = Schemas['SigningKey']
export type Operator = Schemas['Operator']
export type Tenant = Schemas['Tenant']
export type User = Schemas['User']
export type IdentityProvider = Schemas['IdentityProvider']

/** Query keys of the installation administration pages (invalidate by prefix). */
export const installKeys = {
  all: ['install'] as const,
  health: ['install', 'health'] as const,
  tenants: ['install', 'tenants'] as const,
  users: ['install', 'users'] as const,
  providers: ['install', 'providers'] as const,
  sessions: ['install', 'sessions'] as const,
  audit: ['install', 'audit'] as const,
  alerts: ['install', 'alerts'] as const,
  keys: ['install', 'signing-keys'] as const,
  operators: ['install', 'operators'] as const,
}

export const healthQuery = queryOptions({
  queryKey: installKeys.health,
  queryFn: async () => unwrap(await api.GET('/installation/health')),
})

/** Every tenant (follows cursors; used for ID → name lookups and filters). */
export const allTenantsQuery = queryOptions({
  queryKey: [...installKeys.tenants, 'all'],
  queryFn: async () => {
    const out: Tenant[] = []
    let cursor: string | undefined
    for (let i = 0; i < 20; i++) {
      const page = unwrap(await api.GET('/tenants', { params: { query: { limit: 200, cursor } } }))
      out.push(...page.items)
      cursor = page.next_cursor
      if (!cursor) break
    }
    return out
  },
})

export const tenantPagesQuery = infiniteQueryOptions({
  queryKey: [...installKeys.tenants, 'pages'],
  queryFn: async ({ pageParam }) =>
    unwrap(await api.GET('/tenants', { params: { query: { limit: 50, cursor: pageParam || undefined } } })),
  initialPageParam: '',
  getNextPageParam: (last) => nonEmpty(last.next_cursor),
})

export interface UserFilter {
  /** Case-insensitive substring of the name or primary email. */
  query: string
  status: '' | 'active' | 'disabled'
}

export function userPagesQuery(f: UserFilter) {
  return infiniteQueryOptions({
    queryKey: [...installKeys.users, 'pages', f],
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET('/users', {
          params: {
            query: {
              limit: 50,
              cursor: pageParam || undefined,
              q: f.query.trim() || undefined,
              status: f.status || undefined,
            },
          },
        }),
      ),
    initialPageParam: '',
    getNextPageParam: (last) => nonEmpty(last.next_cursor),
  })
}

export function userQuery(id: string) {
  return queryOptions({
    queryKey: [...installKeys.users, 'one', id],
    queryFn: async () => unwrap(await api.GET('/users/{user}', { params: { path: { user: id } } })),
    enabled: !!id,
  })
}

export const providersQuery = queryOptions({
  queryKey: installKeys.providers,
  queryFn: async () => unwrap(await api.GET('/identity-providers')),
})

export function sessionsQuery(user: string | undefined) {
  return queryOptions({
    queryKey: [...installKeys.sessions, user ?? ''],
    queryFn: async () => unwrap(await api.GET('/sessions', { params: { query: { user: nonEmpty(user) } } })),
  })
}

export const alertsQuery = queryOptions({
  queryKey: installKeys.alerts,
  queryFn: async () => unwrap(await api.GET('/installation/alerts')),
})

export const signingKeysQuery = queryOptions({
  queryKey: installKeys.keys,
  queryFn: async () => unwrap(await api.GET('/installation/signing-keys')),
})

export const operatorsQuery = queryOptions({
  queryKey: installKeys.operators,
  queryFn: async () => unwrap(await api.GET('/installation/operators')),
})

/** Audit search filters (empty strings mean "any"). since/until are ISO timestamps. */
export interface AuditFilter {
  actor: string
  target: string
  action: string
  outcome: '' | 'success' | 'failure' | 'denied'
  since: string
  until: string
  tenant: string
}

export const emptyAuditFilter: AuditFilter = {
  actor: '',
  target: '',
  action: '',
  outcome: '',
  since: '',
  until: '',
  tenant: '',
}

/** Audit events newest first; `tenant` scopes to a tenant's own log (audit:read), otherwise the installation log. */
export function auditPagesQuery(scope: { tenant?: string }, f: AuditFilter) {
  return infiniteQueryOptions({
    queryKey: [...installKeys.audit, scope.tenant ?? '*', f],
    queryFn: async ({ pageParam }): Promise<AuditPage> => {
      const query = {
        actor: f.actor.trim() || undefined,
        target: f.target.trim() || undefined,
        action: f.action.trim() || undefined,
        outcome: f.outcome || undefined,
        since: f.since || undefined,
        until: f.until || undefined,
        limit: 50,
        cursor: pageParam || undefined,
      }
      if (scope.tenant)
        return unwrap(await api.GET('/tenants/{tenant}/audit', { params: { path: { tenant: scope.tenant }, query } }))
      return unwrap(await api.GET('/audit', { params: { query: { ...query, tenant: f.tenant || undefined } } }))
    },
    initialPageParam: '',
    getNextPageParam: (last) => nonEmpty(last.next_cursor),
  })
}

/** The message shown when an If-Match precondition fails. */
export const conflictMessage =
  'This was changed by someone else. The latest version has been reloaded; review it and try again.'

/** Rewrites a 412 Precondition Failed into a clear "changed by someone else" error (other errors pass through). */
export function explainConflict(e: unknown): never {
  if (e instanceof ApiError && e.status === 412) throw new ApiError({ detail: conflictMessage, code: e.code }, 412)
  throw e
}

/** Whether an error is an If-Match conflict. */
export function isConflict(e: unknown): boolean {
  return e instanceof ApiError && e.status === 412
}
