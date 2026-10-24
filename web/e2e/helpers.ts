import { spawn, type ChildProcess } from 'node:child_process'
import { readFileSync } from 'node:fs'
import AxeBuilder from '@axe-core/playwright'
import { expect, type APIRequestContext, type Browser, type BrowserContext, type Page } from '@playwright/test'

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

export interface DemoState {
  client_id: string
  client_secret: string
  demo: string
}

export function demoState(): DemoState {
  return JSON.parse(readFileSync(process.env.PORCH_E2E_STATE ?? 'e2e-state.json', 'utf8')) as DemoState
}

/** Starts the demo relying party registered by m2-login.spec.ts and waits until it is healthy. */
export async function startDemo(state: DemoState): Promise<ChildProcess> {
  const port = new URL(state.demo).port
  const demo = spawn(process.env.PORCH_E2E_DEMO_BIN ?? '../bin/demo-app', [], {
    env: {
      ...process.env,
      PORCH_ISSUER: BASE,
      DEMO_CLIENT_ID: state.client_id,
      DEMO_CLIENT_SECRET: state.client_secret,
      DEMO_REDIRECT_URL: `${state.demo}/callback`,
      DEMO_POST_LOGOUT_URL: `${state.demo}/`,
      DEMO_RESOURCE: 'https://api.smith.example',
      DEMO_LISTEN: `127.0.0.1:${port}`,
      DEMO_INSECURE_COOKIES: 'true',
    },
    stdio: 'ignore',
  })
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch(`${state.demo}/healthz`)).ok) return demo
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 200))
  }
  demo.kill()
  throw new Error('demo app did not start')
}

/** A browser context signed in as the installation owner (saved by m2-login.spec.ts right after setup). */
export async function ownerContext(browser: Browser): Promise<BrowserContext> {
  return browser.newContext({ storageState: process.env.PORCH_E2E_OWNER_STATE ?? 'e2e-owner.json' })
}

/** Like apiCall, but returns the status and body instead of asserting success. */
export async function apiTry(
  req: APIRequestContext,
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  const me = await req.get(`${BASE}/api/v1/me`)
  const csrf = ((await me.json()) as { csrf_token: string }).csrf_token
  const res = await req.fetch(`${BASE}/api/v1${path}`, {
    method,
    headers: { 'X-Porch-CSRF': csrf, Origin: BASE, 'Content-Type': 'application/json' },
    data: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  return { status: res.status(), body: text ? (JSON.parse(text) as Record<string, unknown>) : null }
}
