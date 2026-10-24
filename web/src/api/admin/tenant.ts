import { infiniteQueryOptions, queryOptions } from '@tanstack/react-query'
import { api, ApiError, check, unwrap, type Schemas } from '../client'
import { ifMatch } from '../admin'

export type Member = Schemas['Member']
export type Invite = Schemas['Invite']
export type Application = Schemas['Application']
export type CreatedApplication = Schemas['CreatedApplication']
export type CreateApplicationRequest = Schemas['CreateApplicationRequest']
export type UpdateApplicationRequest = Schemas['UpdateApplicationRequest']
export type ClientConfig = Schemas['ClientConfig']
export type OIDCClient = Schemas['OIDCClient']
export type Disclosure = Schemas['Disclosure']
export type AppShare = Schemas['AppShare']
export type ClientSecret = Schemas['ClientSecret']
export type ServiceAccount = Schemas['ServiceAccount']
export type CreatedServiceAccount = Schemas['CreatedServiceAccount']
export type ServiceAccountRequest = Schemas['ServiceAccountRequest']
export type ServiceAccountUpdate = Schemas['ServiceAccountUpdate']
export type Tenant = Schemas['Tenant']
export type UpdateTenantRequest = Schemas['UpdateTenantRequest']
export type DomainRule = Schemas['DomainRule']
export type CreateDomainRuleRequest = Schemas['CreateDomainRuleRequest']
export type IdentityProvider = Schemas['IdentityProvider']
export type User = Schemas['User']

/** Query keys of tenant administration data (all start with ['tenant', tenant] so a tenant can be invalidated at once). */
export const tenantKeys = {
  all: (t: string) => ['tenant', t] as const,
  tenant: (t: string) => ['tenant', t, 'settings'] as const,
  members: (t: string) => ['tenant', t, 'members'] as const,
  invites: (t: string) => ['tenant', t, 'invites'] as const,
  apps: (t: string) => ['tenant', t, 'applications'] as const,
  app: (t: string, app: string) => ['tenant', t, 'applications', app] as const,
  shares: (t: string, app: string) => ['tenant', t, 'applications', app, 'shares'] as const,
  serviceAccounts: (t: string) => ['tenant', t, 'service-accounts'] as const,
  domainRules: (t: string) => ['tenant', t, 'domain-rules'] as const,
}

const conflictMessage =
  'This item was changed by someone else since you loaded it. Reload to see the latest version, then retry.'

/** Whether an error is a failed If-Match precondition (someone else changed the resource). */
export function isConflict(e: unknown): boolean {
  return e instanceof ApiError && e.status === 412
}

/** Rewrites 412 failures into a clear "changed by someone else" message. */
async function guarded<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn()
  } catch (e) {
    if (isConflict(e)) throw new ApiError({ detail: conflictMessage, code: (e as ApiError).code }, 412)
    throw e
  }
}

// ---- tenant ----

export const tenantQuery = (t: string) =>
  queryOptions({
    queryKey: tenantKeys.tenant(t),
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}', { params: { path: { tenant: t } } })),
  })

export const updateTenant = (t: string, version: number, body: UpdateTenantRequest) =>
  guarded(async () =>
    unwrap(await api.PATCH('/tenants/{tenant}', { params: { path: { tenant: t }, header: ifMatch(version) }, body })),
  )

export const deleteTenant = (t: string, version: number) =>
  guarded(async () => {
    check(await api.DELETE('/tenants/{tenant}', { params: { path: { tenant: t }, header: ifMatch(version) } }))
  })

// ---- members ----

export const membersQuery = (t: string) =>
  infiniteQueryOptions({
    queryKey: tenantKeys.members(t),
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET('/tenants/{tenant}/members', {
          params: { path: { tenant: t }, query: { limit: 50, ...(pageParam ? { cursor: pageParam } : {}) } },
        }),
      ),
    initialPageParam: '',
    getNextPageParam: (last) => last.next_cursor,
  })

export const addMember = async (t: string, userId: string) =>
  unwrap(await api.POST('/tenants/{tenant}/members', { params: { path: { tenant: t } }, body: { user_id: userId } }))

export const setMemberStatus = (t: string, m: Member, status: Member['status']) =>
  guarded(async () =>
    unwrap(
      await api.PATCH('/tenants/{tenant}/members/{member}', {
        params: { path: { tenant: t, member: m.id }, header: ifMatch(m.version) },
        body: { status },
      }),
    ),
  )

export const removeMember = (t: string, m: Member) =>
  guarded(async () => {
    check(
      await api.DELETE('/tenants/{tenant}/members/{member}', {
        params: { path: { tenant: t, member: m.id }, header: ifMatch(m.version) },
      }),
    )
  })

/** Installation users (operators only), for choosing who to add to a tenant. */
export const usersQuery = (email: string) =>
  queryOptions({
    queryKey: ['users', 'picker', email],
    queryFn: async () =>
      unwrap(
        await api.GET('/users', { params: { query: { limit: 200, status: 'active', ...(email ? { email } : {}) } } }),
      ),
  })

// ---- invites ----

export const invitesQuery = (t: string) =>
  queryOptions({
    queryKey: tenantKeys.invites(t),
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/invites', { params: { path: { tenant: t } } })),
  })

export const createInvite = async (t: string, email: string, validSeconds: number) =>
  unwrap(
    await api.POST('/tenants/{tenant}/invites', {
      params: { path: { tenant: t } },
      body: { email, valid_seconds: validSeconds },
    }),
  )

export const deleteInvite = async (t: string, id: string) => {
  check(await api.DELETE('/tenants/{tenant}/invites/{invite}', { params: { path: { tenant: t, invite: id } } }))
}

// ---- applications ----

export const applicationsQuery = (t: string) =>
  queryOptions({
    queryKey: tenantKeys.apps(t),
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/applications', { params: { path: { tenant: t } } })),
  })

export const applicationQuery = (t: string, app: string) =>
  queryOptions({
    queryKey: tenantKeys.app(t, app),
    queryFn: async () =>
      unwrap(await api.GET('/tenants/{tenant}/applications/{app}', { params: { path: { tenant: t, app } } })),
  })

export const createApplication = async (t: string, body: CreateApplicationRequest) =>
  unwrap(await api.POST('/tenants/{tenant}/applications', { params: { path: { tenant: t } }, body }))

export const updateApplication = (t: string, a: Application, body: UpdateApplicationRequest) =>
  guarded(async () =>
    unwrap(
      await api.PATCH('/tenants/{tenant}/applications/{app}', {
        params: { path: { tenant: t, app: a.id }, header: ifMatch(a.version) },
        body,
      }),
    ),
  )

export const deleteApplication = (t: string, a: Application) =>
  guarded(async () => {
    check(
      await api.DELETE('/tenants/{tenant}/applications/{app}', {
        params: { path: { tenant: t, app: a.id }, header: ifMatch(a.version) },
      }),
    )
  })

export const rotateClientSecret = async (t: string, app: string) =>
  unwrap(await api.POST('/tenants/{tenant}/applications/{app}/rotate-secret', { params: { path: { tenant: t, app } } }))

export const sharesQuery = (t: string, app: string) =>
  queryOptions({
    queryKey: tenantKeys.shares(t, app),
    queryFn: async () =>
      unwrap(await api.GET('/tenants/{tenant}/applications/{app}/shares', { params: { path: { tenant: t, app } } })),
  })

export const shareApplication = async (t: string, app: string, target: string) => {
  check(
    await api.POST('/tenants/{tenant}/applications/{app}/shares', {
      params: { path: { tenant: t, app } },
      body: { tenant: target },
    }),
  )
}

export const unshareApplication = async (t: string, app: string, target: string) => {
  check(
    await api.DELETE('/tenants/{tenant}/applications/{app}/shares/{target}', {
      params: { path: { tenant: t, app, target } },
    }),
  )
}

// ---- service accounts ----

export const serviceAccountsQuery = (t: string) =>
  queryOptions({
    queryKey: tenantKeys.serviceAccounts(t),
    queryFn: async () =>
      unwrap(await api.GET('/tenants/{tenant}/service-accounts', { params: { path: { tenant: t } } })),
  })

export const createServiceAccount = async (t: string, body: ServiceAccountRequest) =>
  unwrap(await api.POST('/tenants/{tenant}/service-accounts', { params: { path: { tenant: t } }, body }))

export const updateServiceAccount = (t: string, sa: ServiceAccount, body: ServiceAccountUpdate) =>
  guarded(async () =>
    unwrap(
      await api.PATCH('/tenants/{tenant}/service-accounts/{sa}', {
        params: { path: { tenant: t, sa: sa.id }, header: ifMatch(sa.version) },
        body,
      }),
    ),
  )

export const deleteServiceAccount = (t: string, sa: ServiceAccount) =>
  guarded(async () => {
    check(
      await api.DELETE('/tenants/{tenant}/service-accounts/{sa}', {
        params: { path: { tenant: t, sa: sa.id }, header: ifMatch(sa.version) },
      }),
    )
  })

export const rotateServiceAccountSecret = async (t: string, sa: string) =>
  unwrap(
    await api.POST('/tenants/{tenant}/service-accounts/{sa}/rotate-secret', { params: { path: { tenant: t, sa } } }),
  )

// ---- domain rules (installation operators) ----

export const domainRulesQuery = (t: string) =>
  queryOptions({
    queryKey: tenantKeys.domainRules(t),
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/domain-rules', { params: { path: { tenant: t } } })),
  })

export const providersQuery = queryOptions({
  queryKey: ['identity-providers'],
  queryFn: async () => unwrap(await api.GET('/identity-providers')),
})

export const createDomainRule = async (t: string, body: CreateDomainRuleRequest) =>
  unwrap(await api.POST('/tenants/{tenant}/domain-rules', { params: { path: { tenant: t } }, body }))

export const deleteDomainRule = (t: string, r: DomainRule) =>
  guarded(async () => {
    check(
      await api.DELETE('/tenants/{tenant}/domain-rules/{rule}', {
        params: { path: { tenant: t, rule: r.id }, header: ifMatch(r.version) },
      }),
    )
  })

// ---- helpers ----

/** Splits a textarea into trimmed, non-empty lines. */
export function lines(s: string): string[] {
  return s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean)
}

/** Formats a timestamp for tables. */
export function when(ts: string | undefined | null): string {
  return ts ? new Date(ts).toLocaleString() : '—'
}

/** Formats a duration in seconds as a short human string. */
export function seconds(n: number): string {
  if (n % 86400 === 0 && n >= 86400) return `${n / 86400} d`
  if (n % 3600 === 0 && n >= 3600) return `${n / 3600} h`
  if (n % 60 === 0 && n >= 60) return `${n / 60} min`
  return `${n} s`
}
