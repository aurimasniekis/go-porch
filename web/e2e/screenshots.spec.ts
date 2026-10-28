import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test'
import { apiCall, BASE, googleLogin, ownerContext, settle } from './helpers'

// Documentation screenshots (scripts/screenshots.sh). Skipped unless SCREENSHOTS_OUT is set, so the normal e2e
// suite and CI never run it. Runs after m2-login.spec.ts on the same throwaway server (tenant smith, the fake Google
// users Ada/Bob/Dave). Application icons and the background image are downloaded by Porch, so this needs the network.
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

/** Captures `<name>-light.png` and, by switching the emulated colour scheme (the UI follows it live), `<name>-dark.png`. */
async function shot(page: Page, name: string, opts: ShotOptions = {}) {
  if (opts.size) await page.setViewportSize(opts.size)
  // Toasts from the seeding steps would cover the page.
  for (const b of await page.getByRole('button', { name: 'Close notification' }).all()) {
    await b.dispatchEvent('click').catch(() => undefined)
  }
  await expect(page.locator('.mantine-Notification-root')).toHaveCount(0, { timeout: 15_000 })
  await page.waitForLoadState('networkidle')
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme })
    await expect(page.locator('html')).toHaveAttribute('data-mantine-color-scheme', scheme)
    await settle(page)
    await page.screenshot({ path: join(OUT, `${name}-${scheme}.png`), fullPage: opts.fullPage ?? false })
  }
  await page.emulateMedia({ colorScheme: 'light' })
}

async function signedIn(browser: Browser, who: string, colorScheme: 'light' | 'dark' = 'light') {
  const ctx = await browser.newContext({ ...VIEW, colorScheme })
  const page = await ctx.newPage()
  await googleLogin(page, who)
  await expect(page.getByRole('heading', { name: 'My applications' })).toBeVisible()
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
    let jane = ''
    for (const [name, email] of [
      ['Jane Jones', 'jane@jones.example'],
      ['Tom Jones', 'tom@jones.example'],
    ]) {
      const u = await apiCall(r, 'POST', '/users', { display_name: name, primary_email: email })
      await apiCall(r, 'POST', '/tenants/jones/members', { user_id: u?.id })
      if (name === 'Jane Jones') jane = String(u?.id)
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
    const holidays = await apiCall(r, 'POST', '/tenants/smith/resources', {
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

    // Self-hosted applications people actually run, with their logos (theSVG brand logos where it has them,
    // dashboard-icons otherwise), grouped as the launcher shows them.
    const oidc = (host: string, path: string) => ({
      kind: 'oidc',
      launch_url: `https://${host}/`,
      client: { redirect_uris: [`https://${host}${path}`], grant_types: ['authorization_code', 'refresh_token'] },
    })
    const fwd = (host: string) => ({ kind: 'forward_auth', hosts: [host], launch_url: `https://${host}/` })
    const apps: Obj[] = [
      {
        slug: 'jellyfin',
        name: 'Jellyfin',
        group: 'Media',
        description: 'Films and series for movie night',
        icon: { source: 'dashboard_icons', ref: 'jellyfin' },
        ...fwd('tv.smith.example'),
      },
      {
        slug: 'immich',
        name: 'Immich',
        group: 'Media',
        description: 'Photos from every phone in the house',
        icon: { source: 'dashboard_icons', ref: 'immich' },
        ...oidc('photos.smith.example', '/auth/login'),
      },
      {
        slug: 'nextcloud',
        name: 'Nextcloud',
        group: 'Documents',
        description: 'Files and calendars',
        icon: { source: 'thesvg', ref: 'nextcloud' },
        ...oidc('cloud.smith.example', '/apps/user_oidc/code'),
      },
      {
        slug: 'paperless',
        name: 'Paperless-ngx',
        group: 'Documents',
        description: 'Scanned letters and receipts',
        icon: { source: 'dashboard_icons', ref: 'paperless-ngx' },
        ...fwd('docs.smith.example'),
      },
      {
        slug: 'home-assistant',
        name: 'Home Assistant',
        group: 'Home',
        description: 'Lights, heating and the door',
        icon: { source: 'thesvg', ref: 'home-assistant' },
        ...fwd('home.smith.example'),
      },
      {
        slug: 'grafana',
        name: 'Grafana',
        group: 'Infrastructure',
        description: 'Dashboards for the home lab',
        icon: { source: 'thesvg', ref: 'grafana' },
        ...oidc('grafana.smith.example', '/login/generic_oauth'),
      },
      {
        slug: 'vaultwarden',
        name: 'Vaultwarden',
        group: 'Infrastructure',
        description: 'Shared passwords',
        icon: { source: 'dashboard_icons', ref: 'vaultwarden' },
        ...fwd('vault.smith.example'),
      },
      {
        slug: 'gitea',
        name: 'Gitea',
        group: 'Infrastructure',
        description: 'Code and configuration',
        icon: { source: 'dashboard_icons', ref: 'gitea' },
        ...oidc('git.smith.example', '/user/oauth2/porch/callback'),
      },
    ]
    for (const a of apps) await apiCall(r, 'POST', '/tenants/smith/applications', a)
    await apiCall(r, 'POST', '/tenants/smith/applications/jellyfin/shares', { tenant: 'jones' })
    // The demo app and whoami from m2-login.spec.ts are the developer's test apps, not part of the story.
    for (const slug of ['demo-app', 'whoami']) await apiCall(r, 'DELETE', `/tenants/smith/applications/${slug}`)

    // Only the parents may open the password manager and the dashboards: an app:access grant on each application.
    const appUser = await apiCall(r, 'POST', '/tenants/smith/roles', {
      slug: 'app-user',
      name: 'App user',
      description: 'Open an application that is limited to assigned people',
      permissions: ['app:access'],
    })
    for (const slug of ['vaultwarden', 'grafana']) {
      const app = await apiCall(r, 'PATCH', `/tenants/smith/applications/${slug}`, { access_mode: 'assigned' })
      await apiCall(r, 'POST', '/tenants/smith/assignments', {
        subject_type: 'group',
        subject_id: parents?.id,
        role_id: appUser?.id,
        scope_type: 'resource',
        scope_resource_type: 'app',
        scope_resource_id: app?.id,
      })
    }

    // Grandma sees the holiday album until the new year; a nightly job reads every album; a former babysitter is
    // suspended rather than removed, so her history stays.
    const rita = await apiCall(r, 'POST', '/users', { display_name: 'Rita Smith', primary_email: 'rita@smith.example' })
    await apiCall(r, 'POST', '/tenants/smith/members', { user_id: rita?.id })
    await apiCall(r, 'POST', '/tenants/smith/assignments', {
      subject_type: 'user',
      subject_id: rita?.id,
      role_id: viewer?.id,
      scope_type: 'resource',
      scope_resource_type: 'album',
      scope_resource_id: holidays?.id,
      expires_at: '2027-01-06T00:00:00Z',
    })
    const backup = await apiCall(r, 'POST', '/tenants/smith/service-accounts', {
      slug: 'photo-backup',
      name: 'Photo backup',
      description: 'Copies every album to the NAS at night',
      audiences: ['https://photos.smith.example'],
    })
    await apiCall(r, 'POST', '/tenants/smith/assignments', {
      subject_type: 'service_account',
      subject_id: backup?.id,
      role_id: viewer?.id,
      scope_type: 'resource_type',
      scope_resource_type: 'album',
    })
    const nora = await apiCall(r, 'POST', '/users', { display_name: 'Nora Lind', primary_email: 'nora@lind.example' })
    const noraMember = await apiCall(r, 'POST', '/tenants/smith/members', { user_id: nora?.id })
    await apiCall(r, 'PATCH', `/tenants/smith/members/${String(noraMember?.id)}`, { status: 'suspended' })
    for (const email of ['oma@smith.example', 'sitter@lind.example'])
      await apiCall(r, 'POST', '/tenants/smith/invites', { email, valid_seconds: 7 * 86400 })

    // Operators: Jane runs the installation with Olga, and Dave may look at everything without changing it.
    await apiCall(r, 'POST', '/installation/operators', { user_id: jane, role: 'admin' })
    await apiCall(r, 'POST', '/installation/operators', { user_id: id('Dave Smith'), role: 'inspector' })

    // Automation tokens: Terraform's token issues the tokens other integrations use (ADR-0048).
    const tf = await apiCall(r, 'POST', '/installation/automation-tokens', {
      name: 'terraform',
      role: 'admin',
      never_expires: true,
    })
    const asTerraform = async (path: string, body: Obj) => {
      const res = await r.post(`${BASE}/api/v1${path}`, {
        headers: { Authorization: `Bearer ${String(tf?.token)}`, 'Content-Type': 'application/json' },
        data: JSON.stringify(body),
      })
      expect(res.status(), `POST ${path}: ${await res.text()}`).toBe(201)
    }
    await asTerraform('/installation/automation-tokens', {
      name: 'app-catalogue',
      role: 'inspector',
      expires_in_days: 180,
    })
    await asTerraform('/tenants/smith/automation-tokens', {
      name: 'smith-photo-sync',
      permissions: ['app:read', 'group:read'],
      expires_in_days: 90,
    })
    await apiCall(r, 'POST', '/installation/automation-tokens', {
      name: 'monitoring',
      role: 'auditor',
      expires_in_days: 365,
    })

    // Ada's earlier test sign-ins (m2-login.spec.ts) locked her backup login; clear it for the account page.
    await apiCall(r, 'POST', `/users/${id('Ada Smith')}/backup-lockout/unlock`)

    // A landscape behind the sign-in page and the launcher. One named Wikimedia Commons file keeps the captures stable
    // between runs (installations normally pick a category and get a random selection).
    await apiCall(r, 'PUT', '/installation/appearance', {
      title: 'Porch',
      background: {
        providers: [{ source: 'wikimedia', files: ['Lake Bled from the Mountain.jpg'] }],
        rotation: 'daily',
        count: 1,
        refresh: 'never',
      },
    })
  })

  test.afterAll(async () => {
    await owner.close()
  })

  test('sign-in page', async ({ browser }) => {
    // 1× scale: the page is mostly photograph, which needs no retina pixels and would make a multi-megabyte PNG.
    const ctx = await browser.newContext({ ...VIEW, deviceScaleFactor: 1, colorScheme: 'light' })
    const p = await ctx.newPage()
    await p.goto('/login')
    await expect(p.getByRole('link', { name: /Continue with Google/ })).toBeVisible()
    await shot(p, 'login', { size: { width: 1440, height: 780 } })
    await ctx.close()
  })

  test('launcher and the account page', async ({ browser }) => {
    const light = await signedIn(browser, 'Ada Smith')
    await expect(light.page.getByRole('article', { name: 'Grafana' })).toBeVisible()
    await shot(light.page, 'launcher', { size: VIEW.viewport, fullPage: true })
    // Keep only this browser in the session list (the earlier specs signed Ada in several times).
    const sessions = (await (await light.page.request.get(`${BASE}/api/v1/me/sessions`)).json()) as Obj[]
    for (const s of sessions.filter((s) => !s.current))
      await apiCall(light.page.request, 'DELETE', `/me/sessions/${String(s.id)}`)
    await light.page.goto('/account')
    await expect(light.page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible()
    await shot(light.page, 'account', { size: VIEW.viewport, fullPage: true })
    await light.ctx.close()
  })

  test('tenant administration pages', async () => {
    await page.goto(`${T}/members`)
    await expect(page.getByRole('cell', { name: /Nora Lind/ }).first()).toBeVisible()
    await shot(page, 'members', { fullPage: true })

    await page.goto(`${T}/applications`)
    await expect(page.getByRole('cell', { name: /Grafana/ }).first()).toBeVisible()
    await shot(page, 'applications')

    await page.goto(`${T}/assignments`)
    await expect(page.getByText('Photo backup').first()).toBeVisible()
    await shot(page, 'assignments')

    await page.goto(`${T}/groups`)
    await expect(page.getByRole('table', { name: 'Groups' })).toContainText('Parents')
    await page.getByRole('button', { name: 'Members & nesting of Parents' }).click()
    await expect(page.getByRole('dialog', { name: 'Group Parents' })).toContainText('Ada Smith')
    await shot(page, 'groups')
    await page.keyboard.press('Escape')

    await page.goto(`${T}/resources`)
    await expect(page.getByRole('table', { name: 'Resources (indented by parent)' })).toContainText('School events')
    await shot(page, 'resources')

    await page.goto(`${T}/domains`)
    await expect(page.getByRole('cell', { name: 'smith.example' }).first()).toBeVisible()
    await shot(page, 'domains')
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
    await shot(page, 'roles')
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
    await shot(page, 'policy')
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
    // Wider than the other pages, so the candidate grants table fits without its horizontal scroll bar.
    await shot(page, 'simulator', { size: { width: 1680, height: 1050 } })
    await page.setViewportSize(VIEW.viewport)
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
    await shot(page, 'audit', { size: VIEW.viewport })

    await page.goto('/admin/i/appearance')
    await expect(page.getByRole('heading', { name: 'Current images' })).toBeVisible()
    await expect(page.locator('figure img').first()).toBeVisible()
    await shot(page, 'appearance', { fullPage: true })

    await page.goto('/admin/i/health')
    await expect(page.getByRole('table', { name: 'Health checks' })).toBeVisible()
    await shot(page, 'health', { fullPage: true })
  })

  test('installation pages: automation tokens and operators', async () => {
    await page.goto('/admin/i/tokens')
    await expect(page.getByRole('table', { name: 'Automation tokens' })).toContainText('Issued by token terraform')
    await shot(page, 'tokens')

    await page.goto('/admin/i/operators')
    await expect(page.getByRole('table', { name: 'Installation operators' })).toContainText('inspector')
    await shot(page, 'operators')
  })

  test('an inspector sees a tenant read-only', async ({ browser }) => {
    const dave = await signedIn(browser, 'Dave Smith')
    await dave.page.setViewportSize(VIEW.viewport)
    await dave.page.goto(`${T}/applications`)
    await expect(dave.page.getByTestId('read-only-note')).toBeVisible()
    await expect(dave.page.getByRole('row', { name: /Vaultwarden/ })).toBeVisible()
    await shot(dave.page, 'readonly')
    await dave.ctx.close()
  })

  test('phone layout', async ({ browser }) => {
    const phone = { viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true }
    const ctx = await browser.newContext({ ...phone, colorScheme: 'light' })
    const p = await ctx.newPage()
    await googleLogin(p, 'Ada Smith')
    await expect(p.getByRole('heading', { name: 'My applications' })).toBeVisible()
    await shot(p, 'mobile-launcher')
    await ctx.close()

    const state = await owner.storageState()
    const octx = await browser.newContext({ ...phone, colorScheme: 'light', storageState: state })
    const op = await octx.newPage()
    await op.goto(`${T}/applications`)
    await expect(op.getByText('Gitea').first()).toBeVisible()
    await shot(op, 'mobile-admin')
    await octx.close()
  })
})
