import { type ChildProcess } from 'node:child_process'
import { expect, test } from '@playwright/test'
import { demoState, expectAccessible, googleLogin, startDemo } from './helpers'

// M4: the launcher lists the applications a user may open; both an OIDC app and a forward-auth app work from it.
test.describe.serial('M4: launcher → applications', () => {
  let demo: ChildProcess | undefined

  test.beforeAll(async () => {
    demo = await startDemo(demoState())
  })
  test.afterAll(() => {
    demo?.kill()
  })

  test('launcher → forward-auth app (whoami) carries Porch identity headers', async ({ page }) => {
    await googleLogin(page, 'Ada Smith')
    await expect(page.getByRole('heading', { name: 'Your applications' })).toBeVisible()
    await expect(page.getByRole('article', { name: 'Demo app' })).toBeVisible()
    await expectAccessible(page)
    await page
      .getByRole('article', { name: 'Whoami' })
      .getByRole('link', { name: /Open Whoami/ })
      .click()
    await expect(page.getByRole('heading', { name: 'whoami' })).toBeVisible()
    await expect(page.locator('dl')).toContainText('ada@smith.example')
    await expect(page.locator('dl')).toContainText('smith')
  })

  test('launcher → OIDC app signs in with the existing Porch session', async ({ page }) => {
    await googleLogin(page, 'Ada Smith')
    await page
      .getByRole('article', { name: 'Demo app' })
      .getByRole('link', { name: /Open Demo app/ })
      .click()
    await page.getByRole('link', { name: /Sign in with Porch/ }).click()
    // No Porch login page this time: single sign-on straight back to the app.
    await expect(page.locator('body')).toContainText('ada@smith.example')
  })

  test('account page lists sessions and offline grants; revoking a grant works', async ({ page }) => {
    await googleLogin(page, 'Ada Smith')
    await page.goto('/account')
    await expect(page.getByRole('heading', { name: 'Signed-in browsers' })).toBeVisible()
    await expect(page.getByText('(this browser)')).toBeVisible()
    await expectAccessible(page)
    const grants = page.getByRole('heading', { name: 'Applications with offline access' }).locator('..')
    await expect(grants).toContainText('Demo app')
    const before = await grants.getByRole('button', { name: 'Revoke' }).count()
    await grants.getByRole('button', { name: 'Revoke' }).first().click()
    await expect(grants.getByRole('button', { name: 'Revoke' })).toHaveCount(before - 1)
  })
})
