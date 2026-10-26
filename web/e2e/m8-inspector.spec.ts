import { expect, test, type BrowserContext, type Locator, type Page } from '@playwright/test'
import { apiCall, apiTry, BASE, expectAccessible, googleLogin, openedDialog, ownerContext, trackCSP } from './helpers'

// M8: the installation inspector role (ADR-0048). Runs after m2-login.spec.ts on the same server. The owner seeds a
// tenant of its own, grants Bob Smith the inspector role in the UI, and Bob reads every configuration page of that
// tenant without any control to change it. The owner then issues inspector installation tokens (one issued by another
// token) and finally removes Bob's role again so later specs see him as a plain member.
const run = Date.now().toString(36)
const T = `m8-${run}`
const DOMAIN = `m8-${run}.example`
const APP = `M8 App ${run}`
const GROUP = `M8 Group ${run}`
const ROLE = `M8 Role ${run}`
const SA = `M8 Service ${run}`
const MEMBER = `Mira ${run}`

/** Fails when any of the named buttons is on the page (a read-only page shows no change controls). */
async function noButtons(scope: Page | Locator, names: (string | RegExp)[]) {
  for (const name of names) await expect(scope.getByRole('button', { name })).toHaveCount(0)
}

test.describe.serial('M8: installation inspector', () => {
  let owner: BrowserContext
  let page: Page
  let bobCtx: BrowserContext
  let bob: Page
  let csp: string[]
  let bobCSP: string[]

  test.beforeAll(async ({ browser }) => {
    owner = await ownerContext(browser)
    page = await owner.newPage()
    csp = trackCSP(page)
    const r = page.request
    // Step-up protected seeding first, while the owner's setup sign-in is recent.
    await apiCall(r, 'POST', '/tenants', { slug: T, name: `M8 Inspected ${run}` })
    const providers = (await (await r.get(`${BASE}/api/v1/identity-providers`)).json()) as { id: string }[]
    await apiCall(r, 'POST', `/tenants/${T}/domain-rules`, {
      domain: DOMAIN,
      provider_id: providers[0].id,
      evidence_kind: 'workspace_hd',
      mode: 'invite_only',
    })
    await apiCall(r, 'POST', `/tenants/${T}/applications`, {
      slug: 'm8-app',
      name: APP,
      kind: 'oidc',
      client: { redirect_uris: ['http://localhost:9/callback'], grant_types: ['authorization_code'] },
    })
    await apiCall(r, 'POST', `/tenants/${T}/service-accounts`, {
      slug: 'm8-sa',
      name: SA,
      audiences: [`https://api.${T}.example`],
    })
    await apiCall(r, 'POST', `/tenants/${T}/groups`, { slug: 'm8-group', name: GROUP })
    await apiCall(r, 'POST', `/tenants/${T}/roles`, { slug: 'm8-role', name: ROLE, permissions: ['doc:read'] })
    const user = await apiCall(r, 'POST', '/users', { display_name: MEMBER, primary_email: `mira-${run}@m8.test` })
    await apiCall(r, 'POST', `/tenants/${T}/members`, { user_id: user?.id })
    await apiCall(r, 'POST', `/tenants/${T}/invites`, { email: `ivy-${run}@m8.test`, valid_seconds: 86400 })
  })

  test.afterAll(async () => {
    expect(csp).toEqual([])
    expect(bobCSP).toEqual([])
    await bobCtx.close()
    await owner.close()
  })

  test('the owner grants Bob the inspector role', async ({ browser }) => {
    bobCtx = await browser.newContext()
    bob = await bobCtx.newPage()
    bobCSP = trackCSP(bob)
    await googleLogin(bob, 'Bob Smith')
    await expect(bob.getByRole('heading', { name: 'Hello, Bob Smith' })).toBeVisible()
    // Before the grant Bob cannot read the tenant.
    expect((await apiTry(bob.request, 'GET', `/tenants/${T}/applications`)).status).toBeGreaterThanOrEqual(400)

    await page.goto('/admin/i/operators')
    const grant = page.getByRole('form', { name: 'Grant an installation role' })
    await grant.getByRole('textbox', { name: 'User' }).click()
    await page.getByRole('option', { name: /bob@smith\.example/ }).click()
    await grant.getByRole('textbox', { name: 'Role' }).click()
    await page.getByRole('option', { name: 'Inspector' }).click()
    await grant.getByRole('button', { name: 'Grant role' }).click()
    const row = page
      .getByRole('table', { name: 'Installation operators' })
      .getByRole('row', { name: /bob@smith\.example/ })
      .filter({ hasText: 'inspector' })
    await expect(row).toContainText('Reads the configuration of every tenant; changes nothing')
  })

  test('the inspector sees the tenant sections, and no audit log, tokens or installation pages', async () => {
    await bob.goto(`/admin/t/${T}/members`)
    const nav = bob.getByRole('navigation', { name: 'Administration' })
    for (const label of [
      'Members',
      'Invitations',
      'Applications',
      'Service accounts',
      'Groups',
      'Roles',
      'Assignments',
      'Resources',
      'Policies',
      'Domain rules',
      'Settings',
    ])
      await expect(nav.getByRole('link', { name: label, exact: true })).toBeVisible()
    for (const label of ['Audit log', 'Automation tokens', 'Access explorer', 'System health', 'Operators'])
      await expect(nav.getByRole('link', { name: label, exact: true })).toHaveCount(0)
    // The server agrees: reads work, changes are refused.
    expect((await apiTry(bob.request, 'GET', `/tenants/${T}/groups`)).status).toBe(200)
    // Changes are refused like a tenant the caller cannot administer (not found, no existence leak).
    const write = await apiTry(bob.request, 'POST', `/tenants/${T}/groups`, { slug: 'nope', name: 'Nope' })
    expect([403, 404]).toContain(write.status)
  })

  test('members, invitations and settings are read-only', async () => {
    await bob.goto(`/admin/t/${T}/members`)
    await expect(bob.getByRole('heading', { name: 'Members', level: 1 })).toBeVisible()
    await expect(bob.getByRole('row', { name: new RegExp(MEMBER) })).toBeVisible()
    await expect(bob.getByText("Read-only: you can view but not change this tenant's members.")).toBeVisible()
    await noButtons(bob, ['Add member', /^Suspend/, 'Remove'])
    await expectAccessible(bob)

    await bob.goto(`/admin/t/${T}/invites`)
    await expect(bob.getByRole('cell', { name: `ivy-${run}@m8.test` })).toBeVisible()
    await noButtons(bob, ['Create invitation', 'Revoke', 'Delete'])

    await bob.goto(`/admin/t/${T}/settings`)
    await expect(bob.getByRole('textbox', { name: 'Tenant name' })).toHaveValue(`M8 Inspected ${run}`)
    await expect(bob.getByRole('textbox', { name: 'Tenant name' })).toBeDisabled()
    await noButtons(bob, ['Save settings', 'Delete tenant'])
  })

  test('applications are read-only, shares included', async () => {
    await bob.goto(`/admin/t/${T}/applications`)
    await expect(bob.getByRole('row', { name: new RegExp(APP) })).toBeVisible()
    await expect(bob.getByTestId('read-only-note')).toBeVisible()
    await noButtons(bob, ['New application', `Manage ${APP}`])
    await expectAccessible(bob)
    await bob.getByRole('button', { name: `View ${APP}` }).click()
    // A drawer, not a modal: expectAccessible waits for its transition.
    const drawer = bob.getByRole('dialog', { name: APP })
    await expect(drawer).toBeVisible()
    await expect(drawer.getByTestId('copy-Client ID')).toBeVisible()
    await expect(drawer.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue(APP)
    await expect(drawer.getByRole('textbox', { name: 'Name', exact: true })).toBeDisabled()
    await expect(drawer.getByRole('textbox', { name: 'Redirect URIs', exact: true })).toBeDisabled()
    await expect(drawer.getByText('Shared with other tenants')).toBeVisible()
    await expect(drawer.getByText('Not shared.')).toBeVisible()
    await noButtons(drawer, [
      'Save settings',
      'Save launcher settings',
      'Save client',
      'Rotate secret',
      'Share',
      'Delete application',
    ])
    await expect(drawer.getByRole('textbox', { name: 'Share with tenant' })).toHaveCount(0)
    await expectAccessible(bob)
  })

  test('service accounts, groups, roles and assignments are read-only', async () => {
    await bob.goto(`/admin/t/${T}/service-accounts`)
    await expect(bob.getByRole('row', { name: new RegExp(SA) })).toBeVisible()
    await noButtons(bob, ['New service account', `Edit ${SA}`, 'Rotate secret', 'Delete'])

    await bob.goto(`/admin/t/${T}/groups`)
    await expect(bob.getByRole('row', { name: new RegExp(GROUP) })).toBeVisible()
    await noButtons(bob, ['New group', `Rename ${GROUP}`, 'Delete'])
    await expectAccessible(bob)
    await bob.getByRole('button', { name: `Members & nesting of ${GROUP}` }).click()
    const dlg = await openedDialog(bob, `Group ${GROUP}`)
    await expect(dlg.getByText('No direct members.')).toBeVisible()
    await noButtons(dlg, ['Add member', 'Nest'])
    await expect(dlg.getByRole('textbox', { name: 'Add a member' })).toHaveCount(0)
    await dlg.getByRole('button', { name: 'Close', exact: true }).last().click()
    await expect(dlg).toBeHidden()

    await bob.goto(`/admin/t/${T}/roles`)
    const role = bob.getByRole('row', { name: new RegExp(ROLE) })
    await expect(role).toContainText('doc:read')
    await noButtons(bob, ['New role', `Edit role ${ROLE}`, 'Delete'])
    await expectAccessible(bob)

    await bob.goto(`/admin/t/${T}/assignments`)
    await expect(bob.getByRole('heading', { name: 'Assignments', level: 1 })).toBeVisible()
    await noButtons(bob, ['New assignment'])
  })

  test('domain rules are listed read-only', async () => {
    await bob.goto(`/admin/t/${T}/domains`)
    await expect(bob.getByRole('cell', { name: DOMAIN })).toBeVisible()
    await expect(bob.getByText('Read-only: you can view but not change domain rules.')).toBeVisible()
    await noButtons(bob, ['Create rule', 'Delete'])
    await expect(bob.getByRole('textbox', { name: 'Domain' })).toHaveCount(0)
    await expectAccessible(bob)
  })

  test('the owner issues inspector installation tokens, one issued by another token', async ({ request }) => {
    await page.goto('/admin/i/tokens')
    await page.getByRole('button', { name: 'New token' }).click()
    const dialog = await openedDialog(page, 'New automation token')
    await dialog.getByLabel('Name').fill(`m8-inspector-${run}`)
    await dialog.getByRole('textbox', { name: 'Role' }).click()
    await page.getByRole('option', { name: 'Inspector' }).click()
    await expect(dialog.getByRole('textbox', { name: 'Role' })).toHaveValue('Inspector')
    await expectAccessible(page)
    await dialog.getByRole('button', { name: 'Create token' }).click()
    const shown = await openedDialog(page, 'Token created')
    const token = (await shown.getByTestId('copy-Token').textContent())?.trim() ?? ''
    expect(token).toMatch(/^porch_at_/)
    await shown.getByRole('button', { name: 'I have stored the token' }).click()
    await expect(page.getByRole('dialog', { name: 'Token created' })).toHaveCount(0)

    const auth = { Authorization: `Bearer ${token}` }
    expect((await request.get(`${BASE}/api/v1/tenants/${T}/applications`, { headers: auth })).status()).toBe(200)
    const write = await request.post(`${BASE}/api/v1/tenants/${T}/groups`, {
      headers: { ...auth, 'Content-Type': 'application/json' },
      data: JSON.stringify({ slug: 'nope', name: 'Nope' }),
    })
    expect([403, 404]).toContain(write.status())
    // A read-only token issues nothing.
    const minted = await request.post(`${BASE}/api/v1/installation/automation-tokens`, {
      headers: { ...auth, 'Content-Type': 'application/json' },
      data: JSON.stringify({ name: 'nope', role: 'inspector', expires_in_days: 1 }),
    })
    expect(minted.status()).toBe(403)

    const table = page.getByRole('table', { name: 'Automation tokens' })
    const row = table.getByRole('row', { name: new RegExp(`m8-inspector-${run}`) })
    await expect(row).toContainText('installation inspector')
    await expect(row).toContainText('active')

    // An admin token (created by the owner) issues an inspector token; the list names the issuer.
    const admin = await apiCall(page.request, 'POST', '/installation/automation-tokens', {
      name: `m8-parent-${run}`,
      role: 'admin',
      expires_in_days: 2, // an issued token cannot outlive its issuer
    })
    const parentAuth = { Authorization: `Bearer ${String(admin?.token)}` }
    const child = await request.post(`${BASE}/api/v1/installation/automation-tokens`, {
      headers: { ...parentAuth, 'Content-Type': 'application/json' },
      data: JSON.stringify({ name: `m8-child-${run}`, role: 'inspector', expires_in_days: 1 }),
    })
    expect(child.status(), await child.text()).toBe(201)
    await page.reload()
    const childRow = table.getByRole('row', { name: new RegExp(`m8-child-${run}`) })
    await expect(childRow).toContainText(`Issued by token m8-parent-${run}`)
    await expectAccessible(page)

    // Revoking the issuer revokes the token it issued.
    // The child's row mentions the parent too; match the name cell exactly.
    const parentRow = table.getByRole('row').filter({ has: page.getByText(`m8-parent-${run}`, { exact: true }) })
    await parentRow.getByRole('button', { name: 'Revoke' }).click()
    await page
      .getByRole('dialog', { name: `Revoke m8-parent-${run}?` })
      .getByRole('button', { name: 'Revoke' })
      .click()
    await expect(parentRow).toContainText('revoked')
    await page.reload()
    await expect(childRow).toContainText('revoked')
    await row.getByRole('button', { name: 'Revoke' }).click()
    await page
      .getByRole('dialog', { name: `Revoke m8-inspector-${run}?` })
      .getByRole('button', { name: 'Revoke' })
      .click()
    await expect(row).toContainText('revoked')
    expect((await request.get(`${BASE}/api/v1/tenants/${T}/applications`, { headers: auth })).status()).toBe(401)
  })

  test('removing the role ends the inspection', async () => {
    await page.goto('/admin/i/operators')
    const row = page
      .getByRole('table', { name: 'Installation operators' })
      .getByRole('row', { name: /bob@smith\.example/ })
      .filter({ hasText: 'inspector' })
    await row.getByRole('button', { name: 'Remove' }).click()
    await page
      .getByRole('dialog', { name: 'Remove the inspector role?' })
      .getByRole('button', { name: 'Remove' })
      .click()
    await expect(row).toHaveCount(0)
    expect((await apiTry(bob.request, 'GET', `/tenants/${T}/applications`)).status).toBeGreaterThanOrEqual(400)
  })
})
