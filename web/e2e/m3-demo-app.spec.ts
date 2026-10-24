import { type ChildProcess } from 'node:child_process'
import { expect, test } from '@playwright/test'
import { BASE, demoState, startDemo, type DemoState } from './helpers'

// M3 interop: the in-repo demo relying party (go-oidc) signs in through Porch and verifies what Porch issued.
// Runs after m2-login.spec.ts, which registered the demo app and enrolled Ada through the Google domain rule.
test.describe.serial('M3: demo app through Porch', () => {
  let demo: ChildProcess | undefined
  let state: DemoState

  test.beforeAll(async () => {
    state = demoState()
    demo = await startDemo(state)
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
