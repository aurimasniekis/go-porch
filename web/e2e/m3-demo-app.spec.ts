import { spawn, type ChildProcess } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { BASE } from './helpers'

interface State {
  client_id: string
  client_secret: string
  demo: string
}

// M3 interop: the in-repo demo relying party (go-oidc) signs in through Porch and verifies what Porch issued.
// Runs after m2-login.spec.ts, which registered the demo app and enrolled Ada through the Google domain rule.
test.describe.serial('M3: demo app through Porch', () => {
  let demo: ChildProcess | undefined
  let state: State

  test.beforeAll(async () => {
    state = JSON.parse(readFileSync(process.env.PORCH_E2E_STATE ?? 'e2e-state.json', 'utf8')) as State
    const port = new URL(state.demo).port
    demo = spawn(process.env.PORCH_E2E_DEMO_BIN ?? '../bin/demo-app', [], {
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
        if ((await fetch(`${state.demo}/healthz`)).ok) return
      } catch {
        // not up yet
      }
      await new Promise((r) => setTimeout(r, 200))
    }
    throw new Error('demo app did not start')
  })

  test.afterAll(() => {
    demo?.kill()
  })

  test('sign in to the demo app with Porch; tokens verify', async ({ page }) => {
    await page.goto(state.demo)
    await page.getByRole('link', { name: /Sign in with Porch/ }).click()
    // Porch login → Google (fake) → back to Porch → back to the demo app.
    await page.getByRole('link', { name: /Continue with Google/ }).click()
    await page.getByRole('button', { name: /Ada Smith/ }).click()
    await expect(page).toHaveURL(new RegExp(`^${state.demo}/`))
    const body = page.locator('body')
    await expect(body).toContainText('ada@smith.example')
    await expect(body).toContainText('smith')
    await expect(body).toContainText('at+jwt')
    await expect(body).toContainText('https://api.smith.example')
  })

  test('refresh rotates and logout ends the Porch session', async ({ page }) => {
    await page.goto(state.demo)
    await page.getByRole('link', { name: /Sign in with Porch/ }).click()
    await page.getByRole('link', { name: /Continue with Google/ }).click()
    await page.getByRole('button', { name: /Ada Smith/ }).click()
    await page.getByRole('button', { name: /Refresh/ }).click()
    await expect(page.locator('body')).toContainText(/rotated/i)
    await page.getByRole('button', { name: /Sign out|Log out/ }).click()
    await expect(page).toHaveURL(new RegExp(`^${state.demo}/`))
    // The Porch session is gone: Porch's own pages ask to sign in again.
    await page.goto(`${BASE}/account`)
    await expect(page).toHaveURL(/\/login/)
  })
})
