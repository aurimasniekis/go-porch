import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test'
import { apiCall, BASE, googleLogin, ownerContext, settle } from './helpers'

// Documentation screenshots (scripts/screenshots.sh). Skipped unless SCREENSHOTS_OUT is set, so the normal e2e
// suite and CI never run it. Runs after m2-login.spec.ts on the same throwaway server: everything shown is fictional
// (tenant smith, the fake Google users Ada/Bob/Dave, invented users, apps and policies).
const OUT = process.env.SCREENSHOTS_OUT ?? ''
const T = '/admin/t/smith'
const VIEW = { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 }

type Obj = Record<string, unknown>

async function list(page: Page, path: string): Promise<Obj[]> {
  const res = await page.request.get(`${BASE}/api/v1${path}`)
  expect(res.status(), `GET ${path}: ${await res.text()}`).toBe(200)
  return ((await res.json()) as { items: Obj[] }).items
}

interface ShotOptions {
  /** Viewport for this capture (CSS pixels); the page keeps it afterwards. */
  size?: { width: number; height: number }
  fullPage?: boolean
}

async function shot(page: Page, name: string, opts: ShotOptions = {}) {
  if (opts.size) await page.setViewportSize(opts.size)
  // Toasts from the seeding steps would cover the page.
  for (const b of await page.getByRole('button', { name: 'Close notification' }).all()) {
    await b.dispatchEvent('click').catch(() => undefined)
  }
  await expect(page.locator('.mantine-Notification-root')).toHaveCount(0, { timeout: 15_000 })
  await page.waitForLoadState('networkidle')
  await settle(page)
  await page.screenshot({ path: join(OUT, `${name}.png`), fullPage: opts.fullPage ?? false })
}

async function signedIn(browser: Browser, who: string, colorScheme: 'light' | 'dark' = 'light') {
  const ctx = await browser.newContext({ ...VIEW, colorScheme })
  const page = await ctx.newPage()
  await googleLogin(page, who)
  await expect(page.getByRole('heading', { name: 'Your applications' })).toBeVisible()
  return { ctx, page }
}

test.describe.serial('Documentation screenshots', () => {
  test.skip(!OUT, 'set SCREENSHOTS_OUT (scripts/screenshots.sh)')

  let owner: BrowserContext
  let page: Page

  test.beforeAll(async ({ browser }) => {
    mkdirSync(OUT, { recursive: true })
    // Bob and Dave join the tenant through Google (Ada did in m2-login.spec.ts).
    for (const who of ['Bob Smith', 'Dave Smith']) {
      const s = await signedIn(browser, who)
      await s.ctx.close()
    }
    const base = await ownerContext(browser)
    const state = await base.storageState()
    await base.close()
    owner = await browser.newContext({ ...VIEW, colorScheme: 'light', storageState: state })
    page = await owner.newPage()
    const r = page.request

    // People: two children without Google accounts, and a second family.
    for (const [name, email] of [
      ['Mia Smith', 'mia@smith.example'],
      ['Leo Smith', 'leo@smith.example'],
    ]) {
      const u = await apiCall(r, 'POST', '/users', { display_name: name, primary_email: email })
      await apiCall(r, 'POST', '/tenants/smith/members', { user_id: u?.id })
    }
    await apiCall(r, 'POST', '/tenants', { slug: 'jones', name: 'Jones family' })
    for (const [name, email] of [
      ['Jane Jones', 'jane@jones.example'],
      ['Tom Jones', 'tom@jones.example'],
    ]) {
      const u = await apiCall(r, 'POST', '/users', { display_name: name, primary_email: email })
      await apiCall(r, 'POST', '/tenants/jones/members', { user_id: u?.id })
    }
    const members = await list(page, '/tenants/smith/members')
    const id = (name: string) => String(members.find((m) => m.display_name === name)?.user_id)

    // Groups: Family ⊃ Parents, Kids.
    await apiCall(r, 'POST', '/tenants/smith/groups', {
      slug: 'family',
      name: 'Family',
      description: 'Everyone at home',
    })
    const parents = await apiCall(r, 'POST', '/tenants/smith/groups', { slug: 'parents', name: 'Parents' })
    const kids = await apiCall(r, 'POST', '/tenants/smith/groups', { slug: 'kids', name: 'Kids' })
    await apiCall(r, 'PUT', '/tenants/smith/groups/parents/parents/family')
    await apiCall(r, 'PUT', '/tenants/smith/groups/kids/parents/family')
    for (const who of ['Ada Smith', 'Bob Smith'])
      await apiCall(r, 'PUT', `/tenants/smith/groups/parents/members/${id(who)}`)
    for (const who of ['Mia Smith', 'Leo Smith'])
      await apiCall(r, 'PUT', `/tenants/smith/groups/kids/members/${id(who)}`)

    // Resources: a photo library with albums, and a recipe book.
    const photos = await apiCall(r, 'POST', '/tenants/smith/resources', {
      type: 'album',
      slug: 'photos',
      name: 'Photo library',
    })
    await apiCall(r, 'POST', '/tenants/smith/resources', {
      type: 'album',
      slug: 'holidays-2026',
      name: 'Holidays 2026',
      parent_id: photos?.id,
      attributes: { audience: 'family' },
    })
    await apiCall(r, 'POST', '/tenants/smith/resources', {
      type: 'album',
      slug: 'school',
      name: 'School events',
      parent_id: photos?.id,
      attributes: { audience: 'kids' },
    })
    await apiCall(r, 'POST', '/tenants/smith/resources', { type: 'book', slug: 'recipes', name: 'Recipe book' })

    // Roles, a condition and a deny policy, and assignments that use them.
    const viewer = await apiCall(r, 'POST', '/tenants/smith/roles', {
      slug: 'photo-viewer',
      name: 'Photo viewer',
      description: 'Browse albums',
      permissions: ['album:read'],
    })
    const editor = await apiCall(r, 'POST', '/tenants/smith/roles', {
      slug: 'photo-editor',
      name: 'Photo editor',
      description: 'Upload and organise albums',
      permissions: ['album:read', 'album:write', 'album:share'],
    })
    await apiCall(r, 'POST', '/tenants/smith/roles', {
      slug: 'cook',
      name: 'Cook',
      permissions: ['book:read', 'book:write'],
    })
    const daytime = await apiCall(r, 'POST', '/tenants/smith/policies', {
      slug: 'daytime',
      name: 'Daytime only',
      effect: 'condition',
      expression: 'context.hour >= 7 && context.hour < 21',
    })
    await apiCall(r, 'POST', '/tenants/smith/policies', {
      slug: 'home-network-deletes',
      name: 'Deletes only from home',
      effect: 'deny',
      actions: ['album:delete'],
      expression: 'context.network != "trusted"',
    })
    await apiCall(r, 'POST', '/tenants/smith/assignments', {
      subject_type: 'group',
      subject_id: parents?.id,
      role_id: editor?.id,
      scope_type: 'tenant',
    })
    await apiCall(r, 'POST', '/tenants/smith/assignments', {
      subject_type: 'group',
      subject_id: kids?.id,
      role_id: viewer?.id,
      scope_type: 'resource',
      scope_resource_type: 'album',
      scope_resource_id: photos?.id,
      condition_policy_id: daytime?.id,
    })

    // Two more applications next to the demo app and whoami from m2-login.spec.ts.
    await apiCall(r, 'POST', '/tenants/smith/applications', {
      slug: 'family-photos',
      name: 'Family photos',
      kind: 'forward_auth',
      description: 'Albums from every phone in the house',
      hosts: ['photos.smith.example'],
      launch_url: 'https://photos.smith.example/',
    })
    const wiki = await apiCall(r, 'POST', '/tenants/smith/applications', {
      slug: 'recipe-wiki',
      name: 'Recipe wiki',
      kind: 'oidc',
      description: "Grandmother's recipes, finally written down",
      launch_url: 'https://wiki.smith.example/',
      client: {
        redirect_uris: ['https://wiki.smith.example/oauth/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
      },
    })
    await apiCall(r, 'POST', `/tenants/smith/applications/${String(wiki?.id)}/shares`, { tenant: 'jones' })
  })

  test.afterAll(async () => {
    await owner.close()
  })

  test('sign-in page', async ({ browser }) => {
    const ctx = await browser.newContext({ ...VIEW, colorScheme: 'light' })
    const p = await ctx.newPage()
    await p.goto('/login')
    await expect(p.getByRole('link', { name: /Continue with Google/ })).toBeVisible()
    await shot(p, 'login-light', { size: { width: 1440, height: 780 } })
    await ctx.close()
  })

  test('launcher, light and dark, and the account page', async ({ browser }) => {
    const light = await signedIn(browser, 'Ada Smith')
    await expect(light.page.getByRole('article', { name: 'Recipe wiki' })).toBeVisible()
    await shot(light.page, 'launcher-light', { size: { width: 1440, height: 680 } })
    await light.page.goto('/account')
    await expect(light.page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible()
    await shot(light.page, 'account-light', { size: VIEW.viewport, fullPage: true })
    const state = await light.ctx.storageState()
    await light.ctx.close()

    const ctx = await browser.newContext({ ...VIEW, colorScheme: 'dark', storageState: state })
    const p = await ctx.newPage()
    await p.goto('/')
    await expect(p.getByRole('article', { name: 'Recipe wiki' })).toBeVisible()
    await shot(p, 'launcher-dark', { size: { width: 1440, height: 680 } })
    await ctx.close()
  })

  test('tenant administration pages', async () => {
    await page.goto(`${T}/members`)
    await expect(page.getByRole('cell', { name: /Mia Smith/ }).first()).toBeVisible()
    await shot(page, 'members-light')

    await page.goto(`${T}/applications`)
    await expect(page.getByRole('cell', { name: /Recipe wiki/ }).first()).toBeVisible()
    await shot(page, 'applications-light')

    await page.goto(`${T}/assignments`)
    await expect(page.getByText('Photo viewer').first()).toBeVisible()
    await shot(page, 'assignments-light')
  })

  test('role editor with the permission picker', async () => {
    await page.goto(`${T}/roles`)
    await expect(page.getByRole('table', { name: 'Roles' })).toContainText('Photo editor')
    await page.getByRole('button', { name: 'New role' }).click()
    const dlg = page.getByRole('dialog', { name: 'New role' })
    await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill('Recipe reader')
    await dlg.getByRole('textbox', { name: 'Description', exact: true }).fill('Read the recipe book')
    const perms = dlg.getByRole('textbox', { name: 'Permissions', exact: true })
    await perms.fill('book:read')
    await perms.press('Enter')
    await perms.fill('book:')
    await shot(page, 'roles-light')
    await page.keyboard.press('Escape')
    await page.keyboard.press('Escape')
  })

  test('policy editor with live validation', async () => {
    await page.goto(`${T}/policies`)
    await expect(page.getByRole('row', { name: /Daytime only/ })).toBeVisible()
    await page.getByRole('button', { name: 'New policy' }).click()
    const dlg = page.getByRole('dialog', { name: 'New policy' })
    await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill('School nights')
    await dlg
      .getByRole('textbox', { name: 'Expression', exact: true })
      .fill('context.weekday in ["Sat", "Sun"] || context.hour < 20 || resource.attributes.audience == "family"')
    await dlg.getByRole('button', { name: 'Environment v1 reference' }).click()
    await expect(dlg.getByRole('table', { name: 'Policy helper functions' })).toBeVisible()
    await expect(dlg.getByText('Expression compiles against environment v1.')).toBeVisible()
    await shot(page, 'policy-light')
    await page.keyboard.press('Escape')
  })

  test('access simulator explains a decision', async () => {
    await page.goto(`${T}/access`)
    await page.getByRole('tab', { name: 'Simulator' }).click()
    await page.getByRole('textbox', { name: 'Member', exact: true }).click()
    await page
      .getByRole('option', { name: /Mia Smith/ })
      .first()
      .click()
    await page.getByRole('textbox', { name: 'Action', exact: true }).fill('album:read')
    await page.getByRole('radio', { name: 'A resource' }).check()
    await page.getByRole('textbox', { name: 'Resource', exact: true }).click()
    await page
      .getByRole('option', { name: /Holidays 2026/ })
      .first()
      .click()
    await page.getByRole('switch', { name: /Simulate request context/ }).check()
    await page.getByRole('textbox', { name: 'Hour (UTC)' }).fill('16')
    await page.getByRole('button', { name: 'Check access' }).click()
    const decision = page.getByRole('region', { name: 'Decision' })
    await expect(decision.getByText('Allowed', { exact: true })).toBeVisible()
    await decision.scrollIntoViewIfNeeded()
    await shot(page, 'simulator-light')
  })

  test('installation pages: audit and health', async () => {
    await page.goto('/admin/i/audit')
    const table = page.getByRole('table', { name: 'Audit events, newest first' })
    await page.getByRole('textbox', { name: 'Action prefix' }).fill('policy.')
    await page.getByRole('button', { name: 'Apply filters' }).click()
    const toggles = table.getByRole('button', { name: /^Show details of policy\./ })
    await expect(toggles.first()).toBeVisible()
    await toggles.first().click()
    await expect(table.getByText('Chain hash (prefix)')).toBeVisible()
    await shot(page, 'audit-light', { size: VIEW.viewport })

    await page.goto('/admin/i/health')
    await expect(page.getByRole('table', { name: 'Health checks' })).toBeVisible()
    await shot(page, 'health-light', { fullPage: true })
  })
})
