import createClient, { type Middleware } from 'openapi-fetch'
import type { components, paths } from './schema.gen'
import { safeReturnTo } from '@/lib/redirect'

export type Schemas = components['schemas']
export type Me = Schemas['Me']
export type Problem = Schemas['Problem']

/** Header carrying the session's CSRF token on state-changing requests (ADR-0021). */
export const CSRF_HEADER = 'X-Porch-CSRF'

let csrf = ''

export function setCsrfToken(token: string | undefined | null) {
  csrf = token ?? ''
}

/** An API error with its HTTP status, stable code and optional re-authentication action. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly action: string
  readonly fields: { field: string; message: string }[]
  constructor(p: Partial<Problem>, status: number) {
    const extra = p.errors
      ?.map((e) => e.message)
      .filter(Boolean)
      .join('; ')
    const fields = p.fields?.map((f) => `${f.field}: ${f.message}`).join('; ')
    super([p.detail ?? p.title ?? `HTTP ${status}`, fields ?? extra].filter(Boolean).join(' — '))
    this.name = 'ApiError'
    this.status = status
    this.code = p.code ?? ''
    this.action = p.action ?? ''
    this.fields = p.fields ?? []
  }
}

/** Where to go for a re-authentication action, returning to the current page afterwards. */
export function actionUrl(action: string, here = `${window.location.pathname}${window.location.search}`): string {
  const sep = action.includes('?') ? '&' : '?'
  return `${action}${sep}return_to=${encodeURIComponent(safeReturnTo(here))}`
}

const session: Middleware = {
  onRequest({ request }) {
    if (request.method !== 'GET' && request.method !== 'HEAD' && csrf) request.headers.set(CSRF_HEADER, csrf)
    return request
  },
  async onResponse({ response }) {
    if (response.status !== 401 && response.status !== 403) return response
    const body = (await response
      .clone()
      .json()
      .catch(() => ({}))) as Partial<Problem>
    // Federated sessions must re-confirm upstream hourly; the server says where (ADR-0007).
    if (body.code === 'upstream_recheck_required' && body.action) window.location.assign(actionUrl(body.action))
    return response
  },
}

export const api = createClient<paths>({ baseUrl: '/api/v1', headers: { 'X-Porch-Managed-By': 'ui' } })
api.use(session)

function problemOf(e: unknown): Partial<Problem> {
  return typeof e === 'object' && e !== null ? e : {}
}

/** Unwraps an openapi-fetch result or throws an ApiError. */
export function unwrap<T>(res: { data?: T; error?: unknown; response: Response }): T {
  if (res.error !== undefined || res.data === undefined) throw new ApiError(problemOf(res.error), res.response.status)
  return res.data
}

/** Throws an ApiError for a failed result without a body (204 endpoints). */
export function check(res: { error?: unknown; response: Response }): void {
  if (res.error !== undefined || !res.response.ok) throw new ApiError(problemOf(res.error), res.response.status)
}
