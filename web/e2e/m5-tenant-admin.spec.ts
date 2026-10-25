import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { apiCall, BASE, expectAccessible, ownerContext, trackCSP } from './helpers'

// Runs after m2-login.spec.ts on the same server, acting as the installation owner. It creates its own tenants, user,
// applications and service accounts and never touches the smith tenant's objects.
const run = Date.now().toString(36)
const T = `m5t-${run}`
const T2 = `m5u-${run}`
const audience = `https://api.${T}.example`
const sections = ['members', 'invites', 'applications', 'service-accounts', 'domains', 'settings']

/** Runs axe once transitions have finished (elements that are still fading in report false contrast failures). */
async function accessible(page: Page) {
  await page.waitForFunction(() =>
    document
      .getAnimations()
      .every((a) => a.playState !== 'running' || a.effect?.getComputedTiming().iterations === Infinity),
  )
  await expectAccessible(page)
}

test.describe.serial('M5: tenant administration', () => {
  let ctx: BrowserContext
  let page: Page
  let csp: string[]

  test.beforeAll(async ({ browser }) => {
    ctx = await ownerContext(browser)
    page = await ctx.newPage()
    csp = trackCSP(page)
    await apiCall(page.request, 'POST', '/tenants', { slug: T, name: 'M5 Admin Test' })
    await apiCall(page.request, 'POST', '/tenants', { slug: T2, name: 'M5 Share Target' })
    await apiCall(page.request, 'POST', '/users', { display_name: `Mona ${run}`, primary_email: `mona-${run}@m5.test` })
  })

  test.afterAll(async () => {
    expect(csp).toEqual([])
    await ctx.close()
  })

  test('every tenant page loads and is accessible', async () => {
    for (const s of sections) {
      await page.goto(`/admin/t/${T}/${s}`)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      await page.waitForLoadState('networkidle')
      await accessible(page)
    }
    // The installation-wide domain rule of the smith tenant is listed (read only here).
    await page.goto('/admin/t/smith/domains')
    await expect(page.getByRole('cell', { name: 'smith.example' })).toBeVisible()
    await page.getByRole('textbox', { name: 'Evidence' }).click()
    await page.getByRole('option', { name: 'Verified email domain' }).click()
    await expect(page.getByText('Weaker evidence')).toBeVisible()
    await accessible(page)
  })

  test('members: add an installation user, suspend, reactivate and remove', async () => {
    const name = `Mona ${run}`
    await page.goto(`/admin/t/${T}/members`)
    await expect(page.getByText('No members yet')).toBeVisible()
    await page.getByRole('textbox', { name: 'User' }).fill(name)
    await page.getByRole('option', { name: new RegExp(name) }).click()
    await page.getByRole('button', { name: 'Add member' }).click()
    const row = page.getByRole('row', { name: new RegExp(name) })
    await expect(row).toBeVisible()
    await expect(row.getByText('Added manually')).toBeVisible()
    await row.getByRole('button', { name: `Suspend ${name}` }).click()
    await expect(row.getByText('suspended', { exact: true })).toBeVisible()
    await row.getByRole('button', { name: `Reactivate ${name}` }).click()
    await expect(row.getByText('active', { exact: true })).toBeVisible()
    await accessible(page)
    await row.getByRole('button', { name: 'Remove' }).click()
    const dialog = page.getByRole('dialog', { name: `Remove ${name}?` })
    await expect(dialog).toBeVisible()
    await accessible(page)
    await dialog.getByRole('button', { name: 'Remove' }).click()
    await expect(row).toHaveCount(0)
  })

  test('invitations: create and revoke', async () => {
    await page.goto(`/admin/t/${T}/invites`)
    for (const who of ['keep', 'revoke']) {
      await page.getByRole('textbox', { name: 'Email address', exact: true }).fill(`${who}-${run}@m5.test`)
      await page.getByRole('button', { name: 'Create invitation' }).click()
      await expect(page.getByRole('cell', { name: `${who}-${run}@m5.test` })).toBeVisible()
    }
    const row = page.getByRole('row', { name: new RegExp(`revoke-${run}`) })
    await expect(row.getByText('pending')).toBeVisible()
    await row.getByRole('button', { name: 'Revoke' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Revoke' }).click()
    await expect(row).toHaveCount(0)
    await expect(page.getByRole('cell', { name: `keep-${run}@m5.test` })).toBeVisible()
    await accessible(page)
  })

  test('applications: create, edit, share and delete an OIDC app; create a forward-auth app', async () => {
    await page.goto(`/admin/t/${T}/applications`)
    await page.getByRole('button', { name: 'New application' }).click()
    const create = page.getByRole('dialog', { name: 'New application' })
    await expect(create).toBeVisible()
    await accessible(page)
    await create.getByRole('textbox', { name: 'Slug', exact: true }).fill('m5-oidc')
    await create.getByRole('textbox', { name: 'Name', exact: true }).fill('M5 OIDC app')
    await create.getByRole('textbox', { name: 'Redirect URIs', exact: true }).fill('http://localhost:9/callback')
    await create.getByRole('textbox', { name: 'API audiences', exact: true }).fill(audience)
    await create.getByRole('button', { name: 'Create application' }).click()

    // The secret is shown exactly once.
    const secretDialog = page.getByRole('dialog', { name: 'M5 OIDC app created' })
    await expect(secretDialog.getByText('Shown only once')).toBeVisible()
    const secret = (await secretDialog.getByTestId('copy-Client secret').textContent()) ?? ''
    expect(secret.length).toBeGreaterThan(20)
    await accessible(page)
    await secretDialog.getByRole('button', { name: 'I have stored the secret' }).click()

    // The detail drawer opens with connection details.
    const drawer = page.getByRole('dialog', { name: 'M5 OIDC app' })
    await expect(drawer.getByText('Discovery URL')).toBeVisible()
    await expect(drawer.getByTestId('copy-Issuer')).toHaveText(BASE)
    await expect(drawer.getByText('Shared with other tenants')).toBeVisible()
    await accessible(page)

    // Edit settings (PATCH with If-Match).
    await drawer.getByRole('textbox', { name: 'Name', exact: true }).fill('M5 OIDC app renamed')
    await drawer.getByRole('button', { name: 'Save settings' }).click()
    await expect(page.getByText('Application saved')).toBeVisible()
    // Edit the client configuration.
    await drawer.getByRole('textbox', { name: 'Post-logout redirect URIs', exact: true }).fill('http://localhost:9/')
    await drawer.getByRole('button', { name: 'Save client' }).click()
    await expect(page.getByText('Client configuration saved')).toBeVisible()
    await expect(drawer.getByRole('textbox', { name: 'Post-logout redirect URIs', exact: true })).toHaveValue(
      'http://localhost:9/',
    )

    // Share with another tenant (operators only) and stop sharing.
    await drawer.getByRole('textbox', { name: 'Share with tenant' }).click()
    await page.getByRole('option', { name: 'M5 Share Target' }).click()
    await drawer.getByRole('button', { name: 'Share', exact: true }).click()
    await expect(drawer.getByRole('cell', { name: /M5 Share Target/ })).toBeVisible()
    await drawer.getByRole('button', { name: 'Stop sharing' }).click()
    await page.getByRole('dialog', { name: 'Stop sharing with M5 Share Target?' }).getByRole('button').last().click()
    await expect(drawer.getByText('Not shared.')).toBeVisible()

    // Delete.
    await drawer.getByRole('button', { name: 'Delete application' }).click()
    await page
      .getByRole('dialog', { name: 'Delete M5 OIDC app renamed?' })
      .getByRole('button', { name: 'Delete application' })
      .click()
    await expect(page.getByText('Application M5 OIDC app renamed deleted')).toBeVisible()
    await expect(page.getByRole('row', { name: /m5-oidc/ })).toHaveCount(0)

    // Forward-auth: no secret, hosts instead of a client.
    await page.getByRole('button', { name: 'New application' }).click()
    await create.getByText('Forward-auth (reverse proxy)').click()
    await create.getByRole('textbox', { name: 'Slug', exact: true }).fill('m5-fwd')
    await create.getByRole('textbox', { name: 'Name', exact: true }).fill('M5 forward app')
    await create.getByRole('textbox', { name: 'Protected hosts', exact: true }).fill(`${T}.localhost`)
    await accessible(page)
    await create.getByRole('button', { name: 'Create application' }).click()
    const fwd = page.getByRole('dialog', { name: 'M5 forward app' })
    await expect(fwd.getByRole('textbox', { name: 'Protected hosts', exact: true })).toHaveValue(`${T}.localhost`)
    await accessible(page)
    await fwd.getByRole('button', { name: 'Close' }).click()
    await expect(page.getByRole('row', { name: /m5-fwd/ })).toBeVisible()
  })

  test('service accounts: create via the UI, then obtain a token with the client credentials grant', async () => {
    await page.goto(`/admin/t/${T}/service-accounts`)
    await expect(page.getByRole('main').getByRole('link', { name: 'Assignments' })).toBeVisible()
    await page.getByRole('button', { name: 'New service account' }).click()
    const create = page.getByRole('dialog', { name: 'New service account' })
    await accessible(page)
    await create.getByRole('textbox', { name: 'Slug', exact: true }).fill('m5-robot')
    await create.getByRole('textbox', { name: 'Name', exact: true }).fill('M5 robot')
    await create.getByRole('textbox', { name: 'API audiences', exact: true }).fill(audience)
    await create.getByRole('button', { name: 'Create service account' }).click()

    const reveal = page.getByRole('dialog', { name: 'M5 robot created' })
    await expect(reveal.getByText('Shown only once')).toBeVisible()
    const clientId = (await reveal.getByTestId('copy-Client ID').textContent()) ?? ''
    const secret = (await reveal.getByTestId('copy-Client secret').textContent()) ?? ''
    const tokenEndpoint = (await reveal.getByTestId('copy-Token endpoint').textContent()) ?? ''
    expect(tokenEndpoint).toBe(`${BASE}/oauth2/token`)
    await expect(reveal.getByText('grant_type=client_credentials')).toBeVisible()
    await accessible(page)
    await reveal.getByRole('button', { name: 'I have stored the secret' }).click()

    const res = await page.request.post(tokenEndpoint, {
      headers: { Authorization: `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}` },
      form: { grant_type: 'client_credentials', resource: audience },
    })
    expect(res.status(), await res.text()).toBe(200)
    const tok = (await res.json()) as { access_token?: string; token_type?: string }
    expect(tok.access_token?.length ?? 0).toBeGreaterThan(20)
    expect(tok.token_type?.toLowerCase()).toBe('bearer')

    // Edit and delete.
    await page.getByRole('button', { name: 'Edit M5 robot' }).click()
    const edit = page.getByRole('dialog', { name: 'Edit M5 robot' })
    await edit.getByRole('textbox', { name: 'Name', exact: true }).fill('M5 robot v2')
    await edit.getByRole('textbox', { name: 'Access token lifetime (seconds)', exact: true }).fill('300')
    await accessible(page)
    await edit.getByRole('button', { name: 'Save' }).click()
    const row = page.getByRole('row', { name: /M5 robot v2/ })
    await expect(row.getByText('5 min')).toBeVisible()
    await row.getByRole('button', { name: 'Delete' }).click()
    await page.getByRole('dialog', { name: 'Delete M5 robot v2?' }).getByRole('button', { name: 'Delete' }).click()
    await expect(page.getByText('No service accounts yet.')).toBeVisible()
  })

  test('settings: rename the tenant, set session limits, delete another tenant', async () => {
    await page.goto(`/admin/t/${T}/settings`)
    await page.getByRole('textbox', { name: 'Tenant name', exact: true }).fill('M5 Admin Test renamed')
    await page.getByRole('textbox', { name: 'Idle timeout (minutes)', exact: true }).fill('45')
    await page.getByRole('button', { name: 'Save settings' }).click()
    await expect(page.getByText('Tenant settings saved')).toBeVisible()
    await page.reload()
    await expect(page.getByRole('textbox', { name: 'Tenant name', exact: true })).toHaveValue('M5 Admin Test renamed')
    await expect(page.getByRole('textbox', { name: 'Idle timeout (minutes)', exact: true })).toHaveValue('45')
    await accessible(page)

    await page.goto(`/admin/t/${T2}/settings`)
    await page.getByRole('button', { name: 'Delete tenant' }).click()
    const dialog = page.getByRole('dialog', { name: 'Delete M5 Share Target?' })
    const confirm = dialog.getByRole('button', { name: 'Delete tenant' })
    await expect(confirm).toBeDisabled()
    await dialog.getByLabel(`Type ${T2} to confirm`).fill(T2)
    await accessible(page)
    await confirm.click()
    await expect(page.getByText('Tenant M5 Share Target deleted')).toBeVisible()
    await expect(page).not.toHaveURL(new RegExp(T2))
  })
})
