import { queryOptions } from '@tanstack/react-query'
import { api, setCsrfToken, unwrap, type Schemas } from './client'

export const meQuery = queryOptions({
  queryKey: ['me'],
  queryFn: async () => {
    const res = await api.GET('/me')
    if (res.response.status === 401) return null
    const me = unwrap(res)
    setCsrfToken(me.csrf_token)
    return me
  },
})

export const loginOptionsQuery = queryOptions({
  queryKey: ['login-options'],
  queryFn: async () => unwrap(await api.GET('/auth/options')),
})

export const backupStatusQuery = queryOptions({
  queryKey: ['backup-credential'],
  queryFn: async () => unwrap(await api.GET('/me/backup-credential')),
})

export const identitiesQuery = queryOptions({
  queryKey: ['identities'],
  queryFn: async () => unwrap(await api.GET('/me/identities')),
})

export const myAppsQuery = queryOptions({
  queryKey: ['my-apps'],
  queryFn: async () => unwrap(await api.GET('/me/apps')),
})

export const mySessionsQuery = queryOptions({
  queryKey: ['my-sessions'],
  queryFn: async () => unwrap(await api.GET('/me/sessions')),
})

export const myGrantsQuery = queryOptions({
  queryKey: ['my-grants'],
  queryFn: async () => unwrap(await api.GET('/me/grants')),
})

export type Appearance = Omit<Schemas['PublicAppearance'], 'background'> & { background: Schemas['Image'] | null }

/** Title and background of the user-facing pages (public; cached for the page's lifetime). */
export const appearanceQuery = queryOptions({
  queryKey: ['appearance'],
  queryFn: async (): Promise<Appearance> => {
    const a = unwrap(await api.GET('/appearance'))
    // The server sends null when there is no background (the generated type does not say so).
    const bg: unknown = a.background
    return { ...a, background: bg ? (bg as Schemas['Image']) : null }
  },
  staleTime: Infinity,
})
