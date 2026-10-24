import { writeFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'
import { apiCall, expectAccessible, googleLogin, IDP, trackCSP } from './helpers'

const answers = ['Vaivorykštės gatvė 14', 'Massive Attack in Riga, 2004', 'Kudlius the third']
const titles = ['Street of the summer house', 'First concert I paid for', "Grandmother's dog"]
const password = 'correct-Horse-battery-79!'

test.describe.serial('M2: setup, Google login, backup login', () => {
  test('first-time setup creates the owner and configures Google', async ({ page }) => {
    await page.goto('/login')
    await expect(page.getByText('Porch is not set up yet')).toBeVisible()
    await expectAccessible(page)
    await page.goto('/setup')
    await expectAccessible(page)
    await page.getByLabel('Setup token').fill(process.env.PORCH_E2E_SETUP_TOKEN ?? '')
    await page.getByLabel('Your name').fill('Olga Owner')
    await page.getByRole('button', { name: 'Create owner account' }).click()
    await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible()
    await expectAccessible(page)

    // The setup session is fresh, so step-up protected configuration works right away.
    const prov = await apiCall(page.request, 'POST', '/identity-providers', {
      slug: 'google',
      kind: 'google',
      name: 'Google',
      issuer: IDP,
      client_id: 'porch',
      client_secret: 'porch-e2e-secret',
    })
    await apiCall(page.request, 'POST', '/tenants', { slug: 'smith', name: 'Smith family' })
    await apiCall(page.request, 'POST', '/tenants/smith/domain-rules', {
      domain: 'smith.example',
      provider_id: prov?.id,
      evidence_kind: 'workspace_hd',
      mode: 'jit',
    })
    // Register the demo relying party for m3-demo-app.spec.ts (the secret is only returned here).
    const demo = `http://localhost:${process.env.PORCH_E2E_DEMO_PORT ?? '9091'}`
    const app = await apiCall(page.request, 'POST', '/tenants/smith/applications', {
      slug: 'demo-app',
      name: 'Demo app',
      kind: 'oidc',
      launch_url: demo,
      client: {
        redirect_uris: [`${demo}/callback`],
        post_logout_redirect_uris: [`${demo}/`],
        grant_types: ['authorization_code', 'refresh_token'],
        audiences: ['https://api.smith.example'],
      },
      disclosure: { email: true, groups: true, roles: true, entitlements: false },
    })
    const client = app?.client as { client_id: string }
    writeFileSync(
      process.env.PORCH_E2E_STATE ?? 'e2e-state.json',
      JSON.stringify({ client_id: client.client_id, client_secret: app?.client_secret, demo }),
    )
  })

  test('a Workspace user signs in with Google and is enrolled', async ({ page }) => {
    await googleLogin(page, 'Ada Smith')
    await expect(page.getByRole('heading', { name: 'Hello, Ada Smith' })).toBeVisible()
    await expect(page.getByText('Smith family')).toBeVisible()
    await expectAccessible(page)
  })

  test('a consumer account without enrollment is refused', async ({ page }) => {
    await googleLogin(page, 'Carol')
    await expect(page.getByText('not enrolled')).toBeVisible()
  })

  test('the user enrolls a backup login with their own titled answers', async ({ page }) => {
    const csp = trackCSP(page)
    await googleLogin(page, 'Ada Smith')
    await page.getByRole('link', { name: 'Account' }).click()
    await expect(page.getByRole('heading', { name: 'Backup login', exact: true })).toBeVisible()
    await expectAccessible(page)
    await page.getByRole('textbox', { name: 'Backup password', exact: true }).fill(password)
    await page.getByLabel('Repeat password').fill(password)
    for (let i = 0; i < 3; i++) {
      await page.getByLabel(`Recovery title ${i + 1}`).fill(titles[i])
      await page.getByRole('textbox', { name: 'Answer', exact: true }).nth(i).fill(answers[i])
      await page.getByLabel('Type the answer again').nth(i).fill(answers[i].toLowerCase())
    }
    await page.getByRole('button', { name: 'Save backup login' }).click()
    await expect(page.getByText('enrolled', { exact: true })).toBeVisible()
    await expect(page.getByText(`• ${titles[1]}`)).toBeVisible()
    // Mantine's injected <style> elements carry the per-request nonce: no CSP violations, and styles applied.
    expect(csp).toEqual([])
    const radius = await page
      .getByRole('button', { name: 'Rotate backup login' })
      .evaluate((el) => getComputedStyle(el).borderRadius)
    expect(radius).not.toBe('0px')
  })

  test('backup login: titles appear only after the correct password, then answers sign in', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Backup handle or email').fill('ada@smith.example')
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Continue' }).click()
    for (const t of titles) await expect(page.getByLabel(t)).toBeVisible()
    await expectAccessible(page)
    for (let i = 0; i < 3; i++) await page.getByLabel(titles[i]).fill(answers[i])
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('heading', { name: 'Hello, Ada Smith' })).toBeVisible()
  })

  test('a wrong backup password locks backup login but Google still works', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Backup handle or email').fill('ada@smith.example')
    await page.getByLabel('Password').fill('not-the-password')
    await page.getByRole('button', { name: 'Continue' }).click()
    await expect(page.getByText(/invalid credentials/)).toBeVisible()
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: 'Continue' }).click()
    await expect(page.getByText(/invalid credentials/)).toBeVisible()
    await googleLogin(page, 'Ada Smith')
    await expect(page.getByRole('heading', { name: 'Hello, Ada Smith' })).toBeVisible()
  })
})
