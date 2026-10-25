import { expect, test, type Page } from '@playwright/test'
import { BASE, expectAccessible, openedDialog, ownerContext, trackCSP } from './helpers'

// M6: the owner issues an automation token in the UI, uses it as a bearer credential, then revokes it.
test.describe.serial('M6: automation tokens', () => {
  let page: Page
  let csp: string[]

  test.beforeAll(async ({ browser }) => {
    page = await (await ownerContext(browser)).newPage()
    csp = trackCSP(page)
  })

  test('issue, use and revoke an installation token', async ({ request }) => {
    await page.goto('/admin/i/tokens')
    await expect(page.getByRole('heading', { name: 'Automation tokens' })).toBeVisible()
    await expectAccessible(page)
    await page.getByRole('button', { name: 'New token' }).click()
    const dialog = await openedDialog(page, 'New automation token')
    await dialog.getByLabel('Name').fill('terraform')
    await expectAccessible(page)
    await dialog.getByRole('button', { name: 'Create token' }).click()
    const shown = await openedDialog(page, 'Token created')
    await expect(shown.getByText('Shown only once')).toBeVisible()
    await expectAccessible(page)
    const token = (await shown.getByTestId('copy-Token').textContent())?.trim() ?? ''
    expect(token).toMatch(/^porch_at_/)
    await shown.getByRole('button', { name: 'I have stored the token' }).click()

    const auth = { Authorization: `Bearer ${token}` }
    expect((await request.get(`${BASE}/api/v1/tenants`, { headers: auth })).status()).toBe(200)
    // No CSRF token or Origin needed for bearer requests.
    const created = await request.post(`${BASE}/api/v1/tenants`, {
      headers: { ...auth, 'Content-Type': 'application/json', 'X-Porch-Managed-By': 'terraform' },
      data: JSON.stringify({ slug: 'm6-tf', name: 'Terraform tenant' }),
    })
    expect(created.status()).toBe(201)

    await page.reload()
    const row = page.getByRole('table', { name: 'Automation tokens' }).getByRole('row', { name: /terraform/ })
    await expect(row).toContainText('active')
    await expect(row).not.toContainText(token)
    await row.getByRole('button', { name: 'Revoke' }).click()
    await page.getByRole('dialog', { name: 'Revoke terraform?' }).getByRole('button', { name: 'Revoke' }).click()
    await expect(row).toContainText('revoked')
    expect((await request.get(`${BASE}/api/v1/tenants`, { headers: auth })).status()).toBe(401)

    await page.goto('/admin/t/smith/tokens')
    await expect(page.getByRole('heading', { name: 'Automation tokens' })).toBeVisible()
    await expectAccessible(page)
    expect(csp).toEqual([])
  })

  test('an owner issues a token that never expires (ADR-0046)', async ({ request }) => {
    await page.goto('/admin/i/tokens')
    await page.getByRole('button', { name: 'New token' }).click()
    const dialog = await openedDialog(page, 'New automation token')
    await dialog.getByLabel('Name').fill('break-glass')
    await dialog.getByRole('switch', { name: /Never expires/ }).check()
    await expect(dialog.getByText('A token that never expires')).toBeVisible()
    await expect(dialog.getByLabel('Expires in (days)')).toHaveCount(0)
    await expectAccessible(page)
    await dialog.getByRole('button', { name: 'Create token' }).click()
    const shown = await openedDialog(page, 'Token created')
    const token = (await shown.getByTestId('copy-Token').textContent())?.trim() ?? ''
    await shown.getByRole('button', { name: 'I have stored the token' }).click()
    await expect(page.getByRole('dialog', { name: 'Token created' })).toHaveCount(0) // fully closed before axe runs
    expect(
      (await request.get(`${BASE}/api/v1/tenants`, { headers: { Authorization: `Bearer ${token}` } })).status(),
    ).toBe(200)

    const row = page.getByRole('table', { name: 'Automation tokens' }).getByRole('row', { name: /break-glass/ })
    await expect(row).toContainText('never')
    await expect(row).toContainText('active')
    await expectAccessible(page)
    await row.getByRole('button', { name: 'Revoke' }).click()
    await page.getByRole('dialog', { name: 'Revoke break-glass?' }).getByRole('button', { name: 'Revoke' }).click()
    await expect(row).toContainText('revoked')
    expect(csp).toEqual([])
  })

  test('backups page explains how to enable backups', async () => {
    await page.goto('/admin/i/backups')
    await expect(page.getByRole('heading', { name: 'Backups' })).toBeVisible()
    await expect(page.getByText('Backups are not configured')).toBeVisible()
    await expectAccessible(page)
    expect(csp).toEqual([])
  })
})
