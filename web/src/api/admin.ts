import { queryOptions, useMutation, useQuery, useQueryClient, type QueryKey } from '@tanstack/react-query'
import { notifications } from '@mantine/notifications'
import { actionUrl, api, ApiError, unwrap, type Schemas } from './client'

export type AdminCapabilities = Schemas['AdminCapabilities']
export type AdminTenant = Schemas['AdminTenant']

/** What the signed-in user can administer (drives navigation; the server enforces every check). */
export const adminQuery = queryOptions({
  queryKey: ['me', 'admin'],
  queryFn: async () => unwrap(await api.GET('/me/admin')),
})

/** Whether the caller holds perm in the tenant (operators hold every management permission). */
export function can(t: AdminTenant | undefined, perm: string): boolean {
  return !!t && t.permissions.includes(perm)
}

/**
 * Whether the caller may read an area of the tenant (e.g. 'app'): its read permission or the matching manage
 * permission, which also allows the reads (ADR-0048).
 */
export function canRead(t: AdminTenant | undefined, area: string): boolean {
  return can(t, `${area}:read`) || can(t, `${area}:manage`)
}

/** Installation operators and inspectors read installation-wide configuration (domain rules, shares). */
export function readsInstallationConfig(t: AdminTenant | undefined): boolean {
  return t?.via === 'operator' || t?.via === 'inspector'
}

/** The caller's entry in /me/admin for a tenant (slug or ID); undefined while loading or without access. */
export function useAdminTenant(tenant: string): AdminTenant | undefined {
  const caps = useQuery(adminQuery)
  return caps.data?.tenants.find((x) => x.slug === tenant || x.id === tenant)
}

/** Formats an ETag header value for If-Match from a resource version. */
export function ifMatch(version: number): { 'If-Match': string } {
  return { 'If-Match': `"${version}"` }
}

/**
 * Runs an admin mutation: on success shows `success` and invalidates `invalidate`; a reauth_required problem sends the
 * browser through the step-up flow and back to this page; other errors are shown as notifications and rethrown to the
 * caller's onError (forms show field errors).
 */
export function useAdminMutation<TVars, TData>(opts: {
  mutationFn: (vars: TVars) => Promise<TData>
  success?: string | ((data: TData) => string)
  invalidate?: QueryKey[]
  onSuccess?: (data: TData) => void
}) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: opts.mutationFn,
    onSuccess: async (data) => {
      for (const key of opts.invalidate ?? []) await qc.invalidateQueries({ queryKey: key })
      const msg = typeof opts.success === 'function' ? opts.success(data) : opts.success
      if (msg) notifications.show({ color: 'green', message: msg })
      opts.onSuccess?.(data)
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'reauth_required' && e.action) {
        window.location.assign(actionUrl(e.action))
        return
      }
      notifications.show({ color: 'red', title: 'Not saved', message: e.message })
    },
  })
}
