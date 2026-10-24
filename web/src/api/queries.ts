import { queryOptions } from '@tanstack/react-query'
import { api, setCsrfToken, unwrap } from './client'

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
