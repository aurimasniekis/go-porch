import { expect, test, type Browser, type Page } from '@playwright/test'
import { expectAccessible, googleLogin, ownerContext, trackCSP } from './helpers'

// Phones: every page fits the screen width, administration navigation is a drawer, the launcher's links fold into a
// menu, and lists become one card per row. Runs after m2-login.spec.ts (owner, tenant smith, Ada).
const PHONE = { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true }

/** Asserts nothing on the page is wider than the screen (a sideways-scrolling page). */
async function expectFitsWidth(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  )
  expect(overflow, `page is ${String(overflow)}px wider than the screen`).toBeLessThanOrEqual(0)
}

async function ownerOnPhone(browser: Browser) {
  const base = await ownerContext(browser)
  const state = await base.storageState()
  await base.close()
  const ctx = await browser.newContext({ ...PHONE, storageState: state })
  return { ctx, page: await ctx.newPage() }
}

test.describe.serial('Phone layout', () => {
  test('sign-in page, launcher menu and account page fit a phone', async ({ browser }) => {
    const ctx = await browser.newContext(PHONE)
    const page = await ctx.newPage()
    const csp = trackCSP(page)
    await page.goto('/login?all=1')
    await expect(page.getByRole('link', { name: /Continue with Google/ })).toBeVisible()
    await expectFitsWidth(page)

    await googleLogin(page, 'Ada Smith')
    await expect(page.getByRole('heading', { name: 'My applications' })).toBeVisible()
    await expectFitsWidth(page)
    // The top bar's links are in a menu.
    await expect(page.getByRole('link', { name: 'Account', exact: true })).toBeHidden()
    await page.getByRole('button', { name: 'Menu' }).click()
    await expect(page.getByRole('menuitem', { name: 'Sign out' })).toBeVisible()
    await expectAccessible(page)
    await page.getByRole('menuitem', { name: 'Account' }).click()
    await expect(page.getByRole('heading', { name: 'Account', exact: true })).toBeVisible()
    await expectFitsWidth(page)
    await expectAccessible(page)
    expect(csp).toEqual([])
    await ctx.close()
  })

  test('administration: the navigation is a drawer that closes after choosing a page', async ({ browser }) => {
    const { ctx, page } = await ownerOnPhone(browser)
    await page.goto('/admin/t/smith/members')
    await expect(page.getByRole('heading', { name: 'Members', exact: true })).toBeVisible()
    const nav = page.getByRole('navigation', { name: 'Administration' })
    await expect(nav).toBeHidden()
    const burger = page.getByRole('button', { name: 'Navigation' })
    await expect(burger).toHaveAttribute('aria-expanded', 'false')
    await burger.click()
    await expect(burger).toHaveAttribute('aria-expanded', 'true')
    await expect(nav).toBeVisible()
    await expectAccessible(page)
    await nav.getByRole('link', { name: 'Applications' }).click()
    await expect(page.getByRole('heading', { name: 'Applications', exact: true })).toBeVisible()
    await expect(nav).toBeHidden()
    await expectFitsWidth(page)
    await ctx.close()
  })

  test('administration lists become cards that fit the screen', async ({ browser }) => {
    const { ctx, page } = await ownerOnPhone(browser)
    for (const path of [
      '/admin/t/smith/members',
      '/admin/t/smith/applications',
      '/admin/t/smith/audit',
      '/admin/i/users',
      '/admin/i/sessions',
      '/admin/i/providers',
      '/admin/i/health',
    ]) {
      await page.goto(path)
      await expect(page.locator('.porch-list').first()).toBeVisible()
      await expectFitsWidth(page)
    }

    // Each cell carries its column heading; the actions column has none.
    await page.goto('/admin/t/smith/members')
    const row = page.getByRole('table', { name: 'Tenant members' }).locator('tbody tr').first()
    await expect(row.locator('td[data-label="Status"]')).toBeVisible()
    await expect(row.getByRole('button', { name: /^Suspend / })).toBeVisible()
    await expectAccessible(page)

    // The audit row toggle sits in the card's corner and still takes a tap.
    await page.goto('/admin/i/audit')
    const toggle = page.getByRole('button', { name: /^Show details of/ }).first()
    await toggle.tap()
    await expect(page.getByText('Chain hash (prefix)').first()).toBeVisible()
    await expectFitsWidth(page)
    await expectAccessible(page)
    await ctx.close()
  })
})
