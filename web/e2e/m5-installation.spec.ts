import { expect, test, type BrowserContext, type Locator, type Page } from '@playwright/test'
import { BASE, expectAccessible, googleLogin, ownerContext, trackCSP } from './helpers'

/** Waits until a Mantine modal has finished its open transition (axe would measure half-faded colours otherwise). */
async function openedDialog(page: Page, name: string | RegExp): Promise<Locator> {
  const dialog = page.getByRole('dialog', { name })
  await expect(dialog).toBeVisible()
  await expect(dialog).toHaveCSS('opacity', '1')
  await expect(page.locator('.mantine-Modal-overlay').last()).toHaveCSS('opacity', '1')
  return dialog
}

/**
 * expectAccessible once success notifications have auto-closed: Mantine's notification close button has no accessible
 * name (the app-wide <Notifications> / useAdminMutation would need closeButtonProps), which is outside this page set.
 */
async function accessible(page: Page) {
  await expect(page.locator('.mantine-Notification-root')).toHaveCount(0, { timeout: 15_000 })
  await expectAccessible(page)
}

// Runs after m2-login.spec.ts on the same server: acts as the installation owner (Olga) through the saved setup
// session. Never touches tenant smith, provider google, the demo/whoami applications or Ada/Dave.
test.describe.serial('M5: installation administration', () => {
  let ctx: BrowserContext
  let page: Page
  let csp: string[]

  test.beforeAll(async ({ browser }) => {
    ctx = await ownerContext(browser)
    page = await ctx.newPage()
    csp = trackCSP(page)
  })

  test.afterAll(async () => {
    expect(csp).toEqual([])
    await ctx.close()
  })

  test('system health shows checks, counts and keyring, and the audit chain verifies', async () => {
    await page.goto('/admin/i/health')
    await expect(page.getByRole('heading', { name: 'System health' })).toBeVisible()
    const checks = page.getByRole('table', { name: 'Health checks' })
    await expect(checks.getByRole('row', { name: /storage/i })).toContainText('ok')
    await expect(checks.getByRole('row', { name: /readiness/i })).toContainText('ok')
    await expect(checks.getByRole('row', { name: /backups/i })).toContainText('warning')
    await expect(page.getByRole('table', { name: 'Keyring purposes' })).toContainText('field')
    await expect(page.getByRole('table', { name: 'Storage' })).toContainText(/Database size\s*[\d.]+ (B|KiB|MiB)/)
    await accessible(page)

    await page.getByRole('button', { name: 'Verify audit chain' }).click()
    await expect(page.getByText('Audit chain OK')).toBeVisible()
    await expect(page.getByText(/audit events verified: the hash chain is intact/)).toBeVisible()
    await accessible(page)
    expect(csp).toEqual([])
  })

  test('tenants: list links to members and a new tenant is created from the UI', async () => {
    await page.goto('/admin/i/tenants')
    const table = page.getByRole('table', { name: 'Tenants' })
    await expect(table.getByRole('link', { name: 'Smith family' })).toHaveAttribute('href', '/admin/t/smith/members')
    await accessible(page)

    await page.getByRole('button', { name: 'New tenant' }).click()
    const dialog = await openedDialog(page, 'New tenant')
    await dialog.getByLabel('Name').fill('Jones household')
    await expect(dialog.getByLabel('Slug')).toHaveValue('jones-household')
    await accessible(page)
    await dialog.getByRole('button', { name: 'Create tenant' }).click()
    await expect(dialog).toBeHidden()
    await expect(page.getByText('Tenant Jones household created')).toBeVisible()
    const row = table.getByRole('row', { name: /Jones household/ })
    await expect(row.getByRole('link', { name: 'Jones household' })).toHaveAttribute(
      'href',
      '/admin/t/jones-household/members',
    )
    await expect(row).toContainText('active')
    // The new tenant is administrable right away.
    await row.getByRole('link', { name: 'Jones household' }).click()
    await expect(page).toHaveURL(/\/admin\/t\/jones-household\/members/)
  })

  test('users: create and edit a user, then end all of their sessions (step-up)', async () => {
    await page.goto('/admin/i/users')
    await expect(page.getByRole('table', { name: 'Users' }).getByText('Olga Owner (you)')).toBeVisible()
    await accessible(page)

    await page.getByRole('button', { name: 'New user' }).click()
    const create = await openedDialog(page, 'New user')
    await create.getByLabel('Display name').fill('Mia Five')
    await create.getByLabel('Primary email').fill('mia@five.example')
    await accessible(page)
    await create.getByRole('button', { name: 'Create user' }).click()
    await expect(create).toBeHidden()
    await expect(page.getByRole('row', { name: /Mia Five/ })).toContainText('mia@five.example')

    // Search by exact email.
    await page.getByRole('searchbox', { name: 'Search' }).fill('MIA@five')
    await page.getByRole('button', { name: 'Search' }).click()
    await expect(page.getByRole('table', { name: 'Users' }).getByRole('row')).toHaveCount(2)

    await page.getByRole('button', { name: 'Edit Mia Five' }).click()
    const edit = await openedDialog(page, 'Edit Mia Five')
    await accessible(page)
    await edit.getByLabel('Display name').fill('Mia Fivers')
    await edit.getByRole('button', { name: 'Save changes' }).click()
    await expect(edit).toBeHidden()
    await expect(page.getByText('Mia Fivers saved')).toBeVisible()

    await page.getByRole('button', { name: 'End all sessions of Mia Fivers' }).click()
    const confirm = await openedDialog(page, 'End all sessions of Mia Fivers?')
    await accessible(page)
    await confirm.getByRole('button', { name: 'End all sessions' }).click()
    await expect(page.getByText('All sessions of Mia Fivers ended')).toBeVisible()
  })

  test("sessions: Bob's session is listed, filtered by user, and revoking it signs him out", async ({ browser }) => {
    const bobCtx = await browser.newContext()
    const bob = await bobCtx.newPage()
    await googleLogin(bob, 'Bob Smith')
    await expect(bob.getByRole('heading', { name: 'Hello, Bob Smith' })).toBeVisible()
    expect((await bobCtx.request.get(`${BASE}/api/v1/me`)).status()).toBe(200)

    await page.goto('/admin/i/sessions')
    const table = page.getByRole('table', { name: 'Active sessions' })
    await expect(table.getByRole('row', { name: /Olga Owner/ }).first()).toContainText('this session')
    // Other specs may have signed Bob in before; the newest session is listed first.
    await expect(table.getByRole('row', { name: /Bob Smith/ }).first()).toBeVisible()
    await accessible(page)

    // Filter from the users page.
    await page.goto('/admin/i/users')
    await page.getByRole('link', { name: 'Sessions of Bob Smith' }).click()
    await expect(page).toHaveURL(/\/admin\/i\/sessions\?user=/)
    await expect(page.getByText(/Showing sessions of Bob Smith/)).toBeVisible()
    await expect(table.getByRole('row', { name: /Bob Smith/ }).first()).toBeVisible()
    await expect(table.getByRole('row', { name: /Olga Owner/ })).toHaveCount(0)

    // End every session of Bob (his current one is the first row).
    let first = true
    while ((await table.getByRole('row', { name: /Bob Smith/ }).count()) > 0) {
      await table
        .getByRole('row', { name: /Bob Smith/ })
        .first()
        .getByRole('button', { name: 'Revoke session of Bob Smith' })
        .click()
      const dialog = await openedDialog(page, /End this session of Bob Smith/)
      if (first) await accessible(page)
      first = false
      await dialog.getByRole('button', { name: 'Revoke session' }).click()
      await expect(dialog).toBeHidden()
      await expect(page.getByText('Session of Bob Smith ended').first()).toBeVisible()
    }
    await expect(page.getByText('This user has no active sessions.')).toBeVisible()

    expect((await bobCtx.request.get(`${BASE}/api/v1/me`)).status()).toBe(401)
    await bobCtx.close()
  })

  test('audit explorer filters by action prefix and expands an event', async () => {
    await page.goto('/admin/i/audit')
    const table = page.getByRole('table', { name: 'Audit events, newest first' })
    await expect(table).toBeVisible()
    await accessible(page)

    await page.getByRole('textbox', { name: 'Action prefix' }).fill('tenant.')
    await page.getByRole('button', { name: 'Apply filters' }).click()
    const toggles = table.getByRole('button', { name: /^Show details of / })
    await expect(async () => {
      const names = await toggles.evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') ?? ''))
      expect(names.length).toBeGreaterThan(0)
      for (const n of names) expect(n).toMatch(/^Show details of tenant\./)
    }).toPass()
    await expect(table).toContainText('tenant.created')

    await toggles.first().click()
    await expect(table.getByRole('button', { name: /^Hide details of tenant\./ })).toHaveAttribute(
      'aria-expanded',
      'true',
    )
    await expect(table.getByText('Chain hash (prefix)')).toBeVisible()
    await expect(table.getByText('Request ID')).toBeVisible()
    await expect(table.locator('pre')).toContainText('{')
    await accessible(page)

    // An invalid prefix is rejected in the form.
    await page.getByRole('textbox', { name: 'Action prefix' }).fill('Tenant!')
    await page.getByRole('button', { name: 'Apply filters' }).click()
    await expect(page.getByText(/Use lowercase letters, dots or underscores/)).toBeVisible()

    // The tenant audit page uses the same explorer, scoped to the tenant.
    await page.goto('/admin/t/smith/audit')
    await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible()
    await expect(page.getByRole('table', { name: 'Audit events, newest first' })).toBeVisible()
    await accessible(page)
  })

  test('providers, alerts, keys and operators pages load and are accessible', async () => {
    await page.goto('/admin/i/providers')
    const providers = page.getByRole('table', { name: 'Identity providers' })
    await expect(providers.getByRole('row', { name: /Google/ })).toContainText('enabled')
    await accessible(page)
    await page.getByRole('button', { name: 'Edit Google' }).click()
    const edit = await openedDialog(page, 'Edit Google')
    await expect(edit.getByLabel('Client secret')).toHaveValue('')
    await accessible(page)
    await edit.getByRole('button', { name: 'Cancel' }).click()
    await expect(edit).toBeHidden()
    await page.getByRole('button', { name: 'New provider' }).click()
    const create = await openedDialog(page, 'New identity provider')
    await accessible(page)
    await create.getByRole('button', { name: 'Cancel' }).click()
    await expect(create).toBeHidden()

    await page.goto('/admin/i/alerts')
    await expect(page.getByRole('heading', { name: 'Alerts' })).toBeVisible()
    await expect(
      page.getByText('No open alerts. All clear.').or(page.getByRole('list', { name: 'Open alerts' })),
    ).toBeVisible()
    await accessible(page)

    await page.goto('/admin/i/keys')
    await expect(page.getByRole('heading', { name: 'OIDC signing keys' })).toBeVisible()
    await expect(page.getByRole('table', { name: 'Keyring purposes' })).toContainText('signing')
    await accessible(page)
    await page.getByRole('button', { name: 'Rotate signing key' }).click()
    const rotate = await openedDialog(page, 'Rotate signing key')
    await accessible(page)
    await rotate.getByRole('button', { name: 'Cancel' }).click()
    await expect(rotate).toBeHidden()

    await page.goto('/admin/i/operators')
    await expect(
      page.getByRole('table', { name: 'Installation operators' }).getByRole('row', { name: /Olga Owner/ }),
    ).toContainText('owner')
    await accessible(page)
    // Owners grant and remove installation roles (the setup session is still fresh, so step-up passes).
    const grant = page.getByRole('form', { name: 'Grant an installation role' })
    await grant.getByRole('textbox', { name: 'User' }).click()
    await page.getByRole('option', { name: /mia@five\.example/ }).click()
    await grant.getByRole('textbox', { name: 'Role' }).click()
    await page.getByRole('option', { name: 'Auditor' }).click()
    await grant.getByRole('button', { name: 'Grant role' }).click()
    const operators = page.getByRole('table', { name: 'Installation operators' })
    const mia = operators.getByRole('row', { name: /mia@five\.example/ })
    await expect(mia).toContainText('auditor')
    await accessible(page)
    await mia.getByRole('button', { name: 'Remove' }).click()
    const confirm = page.getByRole('dialog', { name: 'Remove the auditor role?' })
    await confirm.getByRole('button', { name: 'Remove' }).click()
    await expect(mia).toBeHidden()
  })
})
