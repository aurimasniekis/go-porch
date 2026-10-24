import { expect, test, type BrowserContext, type Locator, type Page } from '@playwright/test'
import { apiTry, expectAccessible, googleLogin, ownerContext, trackCSP } from './helpers'

// M5: authorization administration in the UI (roles, groups, resources, policies, assignments, access explorer) and
// delegated administration with escalation checks. Runs after m2-login.spec.ts on the same server (tenant smith).
const sfx = Date.now().toString(36).slice(-5)
const ROLE = { name: `Doc reader ${sfx}`, slug: `doc-reader-${sfx}` }
const CHILD = { name: `Team ${sfx}`, slug: `team-${sfx}` }
const PARENT = { name: `Staff ${sfx}`, slug: `staff-${sfx}` }
const RES = { name: `Handbook ${sfx}`, slug: `handbook-${sfx}` }
const SUB = { name: `Chapter ${sfx}`, slug: `chapter-${sfx}` }
const POLICY = { name: `Trusted network ${sfx}`, slug: `trusted-network-${sfx}` }
const HELP = { name: `Helpdesk ${sfx}`, slug: `helpdesk-${sfx}` }
const T = '/admin/t/smith'

/** Opens a Mantine Select/Autocomplete by its label and picks an option. */
async function pick(page: Page, scope: Page | Locator, label: string, option: string | RegExp) {
  await scope.getByRole('textbox', { name: label, exact: true }).click()
  await page.getByRole('option', { name: option }).first().click()
}

/**
 * expectAccessible once toasts are gone: a toast caught mid-fade by axe reports a false colour-contrast failure.
 * dispatchEvent avoids clicking through to a modal overlay.
 */
async function axe(p: Page) {
  const toasts = p.getByRole('button', { name: 'Close notification' })
  for (const b of await toasts.all()) await b.dispatchEvent('click').catch(() => undefined)
  await expect(p.locator('.mantine-Notification-root')).toHaveCount(0, { timeout: 10_000 })
  await expectAccessible(p)
}

async function addTag(scope: Locator, label: string, value: string) {
  const input = scope.getByRole('textbox', { name: label, exact: true })
  await input.fill(value)
  await input.press('Enter')
  // Close the suggestion dropdown (a transient scroll region) before the next step.
  await input.blur()
}

test.describe.serial('M5: authorization admin UI', () => {
  let owner: BrowserContext
  let page: Page
  let csp: string[]
  let dave: BrowserContext

  test.beforeAll(async ({ browser }) => {
    owner = await ownerContext(browser)
    page = await owner.newPage()
    csp = trackCSP(page)
  })
  test.afterAll(async () => {
    await owner.close()
    await dave.close()
  })

  test('Bob and Dave sign in with Google once and join the tenant', async ({ browser }) => {
    const bob = await browser.newContext()
    const bp = await bob.newPage()
    await googleLogin(bp, 'Bob Smith')
    await expect(bp.getByRole('heading', { name: 'Hello, Bob Smith' })).toBeVisible()
    await bob.close()
    dave = await browser.newContext()
    const dp = await dave.newPage()
    await googleLogin(dp, 'Dave Smith')
    await expect(dp.getByRole('heading', { name: 'Hello, Dave Smith' })).toBeVisible()
  })

  test('owner creates a custom role with the permission picker', async () => {
    await page.goto(`${T}/roles`)
    await expect(page.getByRole('heading', { name: 'Roles', level: 1 })).toBeVisible()
    await expect(page.getByRole('table', { name: 'Roles' })).toContainText('Administrator')
    await axe(page)
    await page.getByRole('button', { name: 'New role' }).click()
    const dlg = page.getByRole('dialog', { name: 'New role' })
    await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill(ROLE.name)
    await expect(dlg.getByRole('textbox', { name: 'Slug', exact: true })).toHaveValue(ROLE.slug)
    await addTag(dlg, 'Permissions', 'Not-Valid')
    await expect(dlg.getByText('is not <resource_type>:<action>')).toBeVisible()
    await addTag(dlg, 'Permissions', 'doc:read')
    await axe(page)
    await dlg.getByRole('button', { name: 'Create role' }).click()
    await expect(dlg).toBeHidden()
    const row = page.getByRole('row', { name: new RegExp(ROLE.name) })
    await expect(row).toContainText('doc:read')
    await expect(row).not.toContainText('Not-Valid')
  })

  test('owner creates groups, adds a member and nests them', async () => {
    await page.goto(`${T}/groups`)
    await expect(page.getByRole('heading', { name: 'Groups', level: 1 })).toBeVisible()
    await axe(page)
    for (const g of [CHILD, PARENT]) {
      await page.getByRole('button', { name: 'New group' }).click()
      const dlg = page.getByRole('dialog', { name: 'New group' })
      await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill(g.name)
      await expect(dlg.getByRole('textbox', { name: 'Slug', exact: true })).toHaveValue(g.slug)
      await axe(page)
      await dlg.getByRole('button', { name: 'Create group' }).click()
      await expect(dlg).toBeHidden()
      await expect(page.getByRole('row', { name: new RegExp(g.name) })).toBeVisible()
    }
    await page.getByRole('button', { name: `Members & nesting of ${CHILD.name}` }).click()
    const dlg = page.getByRole('dialog', { name: `Group ${CHILD.name}` })
    await pick(page, dlg, 'Add a member', /Ada Smith/)
    await dlg.getByRole('button', { name: 'Add member' }).click()
    await expect(dlg.getByRole('table', { name: `Direct members of ${CHILD.name}` })).toContainText('Ada Smith')
    await pick(page, dlg, 'Nest into group', new RegExp(PARENT.name))
    await dlg.getByRole('button', { name: 'Nest' }).click()
    await expect(dlg.getByRole('table', { name: `Parent groups of ${CHILD.name}` })).toContainText(PARENT.name)
    await axe(page)
    // The footer button (the header's × is also named "Close").
    await dlg.getByRole('button', { name: 'Close', exact: true }).last().click()
    const row = page.getByRole('row', { name: new RegExp(CHILD.name) })
    await expect(row).toContainText(PARENT.name)
    await expect(row.getByRole('cell').nth(1)).toHaveText('1')
  })

  test('owner creates a resource tree with attributes', async () => {
    await page.goto(`${T}/resources`)
    await expect(page.getByRole('heading', { name: 'Resources', level: 1 })).toBeVisible()
    await axe(page)
    for (const r of [RES, SUB]) {
      await page.getByRole('button', { name: 'New resource' }).click()
      const dlg = page.getByRole('dialog', { name: 'New resource' })
      await dlg.getByRole('textbox', { name: 'Type', exact: true }).fill('doc')
      await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill(r.name)
      await expect(dlg.getByRole('textbox', { name: 'Slug', exact: true })).toHaveValue(r.slug)
      if (r === SUB) {
        await pick(page, dlg, 'Parent resource (optional)', new RegExp(RES.name))
      } else {
        await dlg.getByRole('button', { name: 'Add attribute' }).click()
        await dlg.getByRole('textbox', { name: 'Attribute 1 key' }).fill('classification')
        await dlg.getByRole('textbox', { name: 'Attribute 1 value' }).fill('internal')
      }
      await axe(page)
      await dlg.getByRole('button', { name: 'Create resource' }).click()
      await expect(dlg).toBeHidden()
    }
    const table = page.getByRole('table', { name: 'Resources (indented by parent)' })
    await expect(table.getByRole('row', { name: new RegExp(RES.name) }).first()).toContainText(
      'classification=internal',
    )
    await expect(table.getByRole('row', { name: new RegExp(SUB.name) })).toContainText(`in ${RES.name}`)
    // Deleting warns about the child resource.
    await table
      .getByRole('row', { name: new RegExp(`^${RES.name}`) })
      .getByRole('button', { name: 'Delete' })
      .click()
    const confirm = page.getByRole('dialog', { name: `Delete resource ${RES.name}?` })
    await expect(confirm).toContainText('child resource is deleted too')
    await axe(page)
    await confirm.getByRole('button', { name: 'Cancel' }).click()
  })

  test('owner writes a condition policy with live validation', async () => {
    await page.goto(`${T}/policies`)
    await expect(page.getByRole('heading', { name: 'Policies', level: 1 })).toBeVisible()
    await axe(page)
    await page.getByRole('button', { name: 'New policy' }).click()
    const dlg = page.getByRole('dialog', { name: 'New policy' })
    await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill(POLICY.name)
    const expr = dlg.getByRole('textbox', { name: 'Expression', exact: true })
    await expr.fill('principal.nope == 1')
    await expect(expr).toHaveAttribute('aria-invalid', 'true')
    await expect(dlg.getByText(/nope/).last()).toBeVisible()
    await dlg.getByRole('button', { name: 'Environment v1 reference' }).click()
    await expect(dlg.getByRole('table', { name: 'Policy helper functions' })).toContainText('cidrMatch')
    await expr.fill('context.network == "trusted"')
    await expect(dlg.getByText('Expression compiles against environment v1.')).toBeVisible()
    await expect(expr).not.toHaveAttribute('aria-invalid', 'true')
    // Checked once the error is gone: the theme's input error red (#fa5252) is below AA contrast (reported).
    await axe(page)
    await dlg.getByRole('button', { name: 'Create policy' }).click()
    await expect(dlg).toBeHidden()
    const row = page.getByRole('row', { name: new RegExp(POLICY.name) })
    await expect(row).toContainText('condition')
    await expect(row).toContainText('context.network == "trusted"')
  })

  test('owner assigns the role to the parent group with the condition', async () => {
    await page.goto(`${T}/assignments`)
    await expect(page.getByRole('heading', { name: 'Assignments', level: 1 })).toBeVisible()
    await axe(page)
    await page.getByRole('button', { name: 'New assignment' }).click()
    const dlg = page.getByRole('dialog', { name: 'New assignment' })
    await dlg.getByRole('radio', { name: 'Group' }).check()
    await pick(page, dlg, 'Group', new RegExp(PARENT.name))
    await pick(page, dlg, 'Role', new RegExp(ROLE.name))
    await expect(dlg.getByRole('radio', { name: 'Whole tenant' })).toBeChecked()
    await pick(page, dlg, 'Condition policy (optional)', new RegExp(POLICY.name))
    await axe(page)
    await dlg.getByRole('button', { name: 'Assign role' }).click()
    await expect(dlg).toBeHidden()
    const row = page.getByRole('row', { name: new RegExp(PARENT.name) })
    await expect(row).toContainText(ROLE.name)
    await expect(row).toContainText('Whole tenant')
    await expect(row).toContainText(POLICY.name)
    // Filtering by role narrows the list to this assignment.
    await pick(page, page, 'Filter by role', new RegExp(ROLE.name))
    await expect(page.getByRole('table', { name: 'Role assignments' }).getByRole('row')).toHaveCount(2)
  })

  test('effective permissions show the inherited conditional grant', async () => {
    await page.goto(`${T}/access`)
    await expect(page.getByRole('heading', { name: 'Access explorer', level: 1 })).toBeVisible()
    await expect(page.getByRole('tab', { name: 'Effective permissions' })).toHaveAttribute('aria-selected', 'true')
    await pick(page, page, 'Subject', /Ada Smith/)
    const row = page
      .getByRole('table', { name: 'Effective permissions' })
      .getByRole('row', { name: new RegExp(`doc:read.*${ROLE.slug}`) })
    await expect(row).toContainText(`group:${PARENT.slug}`)
    await expect(row).toContainText('conditional')
    await expect(row).toContainText('tenant')
    await axe(page)
  })

  test('the simulator explains decisions under a simulated context', async () => {
    await page.goto(`${T}/access`)
    await page.getByRole('tab', { name: 'Simulator' }).click()
    await pick(page, page, 'Member', /Ada Smith/)
    await page.getByRole('textbox', { name: 'Action', exact: true }).fill('doc:read')
    await page.getByRole('switch', { name: /Simulate request context/ }).check()
    await axe(page)
    await page.getByRole('button', { name: 'Check access' }).click()
    const decision = page.getByRole('region', { name: 'Decision' })
    await expect(decision.getByText('Allowed', { exact: true })).toBeVisible()
    await expect(decision).toContainText('simulated context')
    await expect(decision).toContainText(CHILD.slug)
    await expect(decision).toContainText(PARENT.slug)
    const cand = decision
      .getByRole('table', { name: 'Candidate grants' })
      .getByRole('row', { name: new RegExp(ROLE.slug) })
    await expect(cand).toContainText(`group:${PARENT.slug}`)
    await expect(cand).toContainText(POLICY.slug)
    await expect(cand).toContainText('✓ applies')
    await expect(decision.getByRole('table', { name: 'Evaluation context' })).toContainText('trusted')
    await axe(page)

    await pick(page, page, 'Network', 'external')
    await page.getByRole('button', { name: 'Check access' }).click()
    await expect(decision.getByText('Denied', { exact: true })).toBeVisible()
    await expect(decision).toContainText('default_deny')
    await expect(decision.getByRole('table', { name: 'Candidate grants' })).toContainText('✗ does not apply')
  })

  test('owner delegates helpdesk administration to Dave', async () => {
    await page.goto(`${T}/roles`)
    await page.getByRole('button', { name: 'New role' }).click()
    const dlg = page.getByRole('dialog', { name: 'New role' })
    await dlg.getByRole('textbox', { name: 'Name', exact: true }).fill(HELP.name)
    for (const p of ['group:manage', 'role:manage', 'member:manage']) await addTag(dlg, 'Permissions', p)
    await dlg.getByRole('button', { name: 'Create role' }).click()
    await expect(dlg).toBeHidden()

    await page.goto(`${T}/assignments`)
    await page.getByRole('button', { name: 'New assignment' }).click()
    const adlg = page.getByRole('dialog', { name: 'New assignment' })
    await pick(page, adlg, 'Member', /Dave Smith/)
    await pick(page, adlg, 'Role', new RegExp(HELP.name))
    await adlg.getByRole('button', { name: 'Assign role' }).click()
    await expect(adlg).toBeHidden()
    await expect(page.getByRole('row', { name: /Dave Smith/ })).toContainText(HELP.name)
  })

  test('Dave sees only his sections and cannot escalate to admin', async () => {
    const dp = await dave.newPage()
    const daveCsp = trackCSP(dp)
    await dp.goto('/admin')
    const nav = dp.getByRole('navigation', { name: 'Administration' })
    for (const s of ['Members', 'Groups', 'Roles', 'Assignments', 'Access explorer'])
      await expect(nav.getByRole('link', { name: s, exact: true })).toBeVisible()
    for (const s of ['Policies', 'Resources', 'Applications', 'Settings'])
      await expect(nav.getByRole('link', { name: s, exact: true })).toHaveCount(0)

    await nav.getByRole('link', { name: 'Assignments', exact: true }).click()
    await expect(dp.getByRole('heading', { name: 'Assignments', level: 1 })).toBeVisible()
    await axe(dp)
    await dp.getByRole('button', { name: 'New assignment' }).click()
    const dlg = dp.getByRole('dialog', { name: 'New assignment' })
    await pick(dp, dlg, 'Member', /Bob Smith/)
    await pick(dp, dlg, 'Role', /Administrator/)
    await dlg.getByRole('button', { name: 'Assign role' }).click()
    const alert = dlg.getByRole('alert').filter({ hasText: 'Privilege escalation refused' })
    await expect(alert).toBeVisible()
    await expect(alert).toContainText('*:*')
    await expect(dlg).toBeVisible()
    await axe(dp)
    expect(daveCsp).toEqual([])

    // Nothing was granted: the owner sees no assignment for Bob.
    const members = await apiTry(page.request, 'GET', '/tenants/smith/members?limit=200')
    const items = (members.body?.items ?? []) as { user_id: string; email?: string }[]
    const bob = items.find((m) => m.email === 'bob@smith.example')
    expect(bob).toBeDefined()
    const as = await apiTry(page.request, 'GET', `/tenants/smith/assignments?subject_id=${bob?.user_id ?? ''}`)
    expect(as.status).toBe(200)
    expect(as.body).toEqual([])
  })

  test('no CSP violations on the owner pages', () => {
    expect(csp).toEqual([])
  })
})
