import AxeBuilder from '@axe-core/playwright'
import { expect, type APIRequestContext, type Page } from '@playwright/test'

export const BASE = process.env.PORCH_E2E_URL ?? 'http://localhost:8080'
export const IDP = process.env.PORCH_E2E_IDP ?? 'http://127.0.0.1:9999'

/** Fails on any WCAG 2.1 A/AA violation. */
export async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze()
  expect(
    results.violations.map(
      (v) => `${v.id}: ${v.help}: ${v.nodes.map((n) => `${n.target.join(' ')} ${n.failureSummary ?? ''}`).join(' | ')}`,
    ),
  ).toEqual([])
}

/** Calls the management API with the page's session (CSRF token from /me). */
export async function apiCall(
  req: APIRequestContext,
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
) {
  const me = await req.get(`${BASE}/api/v1/me`)
  const csrf = ((await me.json()) as { csrf_token: string }).csrf_token
  const res = await req.fetch(`${BASE}/api/v1${path}`, {
    method,
    headers: { 'X-Porch-CSRF': csrf, Origin: BASE, 'Content-Type': 'application/json' },
    data: body === undefined ? undefined : JSON.stringify(body),
  })
  expect(res.status(), `${method} ${path}: ${await res.text()}`).toBeLessThan(300)
  return res.status() === 204 ? null : ((await res.json()) as Record<string, unknown>)
}

export async function googleLogin(page: Page, who: string) {
  await page.goto('/login')
  await page.getByRole('link', { name: /Continue with Google/ }).click()
  await page.getByRole('button', { name: new RegExp(who) }).click()
}

/** Collects CSP violation reports from the browser console; assert it stays empty. */
export function trackCSP(page: Page): string[] {
  const violations: string[] = []
  page.on('console', (m) => {
    if (/Content Security Policy|Refused to (apply|load|execute)/i.test(m.text())) violations.push(m.text())
  })
  return violations
}
