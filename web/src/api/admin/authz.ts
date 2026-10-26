import { queryOptions, type QueryKey } from '@tanstack/react-query'
import { api, ApiError, unwrap, type Schemas } from '../client'
import { adminQuery, can, type AdminTenant } from '../admin'

export type Role = Schemas['Role']
export type Group = Schemas['Group']
export type ResourceDef = Schemas['ResourceDef']
export type PolicyDef = Schemas['PolicyDef']
export type Assignment = Schemas['Assignment']
export type AssignmentRequest = Schemas['AssignmentRequest']
export type EffectiveGrant = Schemas['EffectiveGrant']
export type Decision = Schemas['Decision']
export type AuthzCheckRequest = Schemas['AuthzCheckRequest']
export type Member = Schemas['Member']
export type ServiceAccount = Schemas['ServiceAccount']
export type Application = Schemas['Application']
export type PermissionCatalogue = Schemas['PermissionCatalogue']

/** Query keys of the authorization admin pages; everything of a tenant lives under authzKey(t). */
export const authzKey = (t: string) => ['authz-admin', t] as const

/** What to refresh after a change to the tenant's authorization model (the caller's own powers may change too). */
export function authzInvalidate(t: string): QueryKey[] {
  return [authzKey(t), adminQuery.queryKey]
}

const path = (tenant: string) => ({ params: { path: { tenant } } })

export const permissionsQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'permissions'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/permissions', path(t))),
  })

export const rolesQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'roles'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/roles', path(t))),
  })

export const groupsQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'groups'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/groups', path(t))),
  })

export const resourcesQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'resources'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/resources', path(t))),
  })

export const policiesQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'policies'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/policies', path(t))),
  })

export const assignmentsQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'assignments'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/assignments', path(t))),
  })

/** Who may list tenant members (GET /tenants/{t}/members): member readers and managers, group and role managers. */
export function mayListMembers(t: AdminTenant | undefined): boolean {
  return can(t, 'member:read') || can(t, 'member:manage') || can(t, 'group:manage') || can(t, 'role:manage')
}

/** Every member of the tenant (follows next_cursor; bounded). */
export const membersQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'members'],
    queryFn: async () => {
      const out: Member[] = []
      let cursor: string | undefined
      for (let i = 0; i < 50; i++) {
        const page = unwrap(
          await api.GET('/tenants/{tenant}/members', {
            params: { path: { tenant: t }, query: { limit: 200, ...(cursor ? { cursor } : {}) } },
          }),
        )
        out.push(...page.items)
        cursor = page.next_cursor
        if (!cursor) break
      }
      return out
    },
  })

export const serviceAccountsQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'service-accounts'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/service-accounts', path(t))),
  })

export const applicationsQuery = (t: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'applications'],
    queryFn: async () => unwrap(await api.GET('/tenants/{tenant}/applications', path(t))),
  })

export const effectiveQuery = (t: string, subjectType: 'user' | 'service_account', subjectId: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'effective', subjectType, subjectId],
    queryFn: async () =>
      unwrap(
        await api.GET('/tenants/{tenant}/authz/effective', {
          params: { path: { tenant: t }, query: { subject_type: subjectType, subject_id: subjectId } },
        }),
      ),
  })

/** Compiles an expression without saving it (live validation in the policy editor). */
export const validatePolicyQuery = (t: string, expression: string) =>
  queryOptions({
    queryKey: [...authzKey(t), 'validate', expression],
    queryFn: async () =>
      unwrap(await api.POST('/tenants/{tenant}/policies/validate', { ...path(t), body: { expression } })),
    staleTime: Infinity,
    retry: false,
  })

function orEmpty<T>(v: T[] | null | undefined): T[] {
  return v ?? []
}

/**
 * The server encodes empty trace lists as null (Go nil slices) although the schema declares arrays; normalise them so
 * the UI can rely on the declared shape.
 */
export function normalizeDecision(d: Decision): Decision {
  return {
    ...d,
    trace: {
      ...d.trace,
      groups: orEmpty(d.trace.groups),
      candidates: orEmpty(d.trace.candidates),
      deny_policies: orEmpty(d.trace.deny_policies),
    },
  }
}

export const CONFLICT_MESSAGE = 'This was changed by someone else in the meantime. Reload the page and try again.'

/** Rewrites a 412 (stale If-Match) into a clear "changed by someone else, reload" error. */
export async function conflictAware<T>(p: Promise<T>): Promise<T> {
  try {
    return await p
  } catch (e) {
    if (e instanceof ApiError && e.status === 412) throw new ApiError({ detail: CONFLICT_MESSAGE, code: e.code }, 412)
    throw e
  }
}

/** A delegated administrator tried to grant what they do not hold (ADR-0038). */
export function isEscalation(e: unknown): e is ApiError {
  return e instanceof ApiError && e.code === 'privilege_escalation'
}

/** The permissions an escalation error says the caller is missing. */
export function missingPermissions(e: ApiError): string[] {
  const f = e.fields.find((x) => x.field === 'permissions')
  const src = f?.message.replace(/^not held:\s*/, '') ?? e.message.replace(/^.*do not hold:\s*/, '').split(' — ')[0]
  return src
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

/** Display name of a member: name, else email, else the user ID. */
export function memberLabel(m: Member): string {
  if (m.display_name && m.email) return `${m.display_name} (${m.email})`
  return m.display_name ?? m.email ?? m.user_id
}
