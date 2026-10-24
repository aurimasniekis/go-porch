import { fileURLToPath } from 'node:url'
import { expect, test, type BrowserContext, type Page } from '@playwright/test'
import { expectAccessible, googleLogin, ownerContext, settle, trackCSP } from './helpers'

// Appearance and the launcher (ADR-0045). Runs after m2-login.spec.ts on the same server as the installation owner.
// Backgrounds stay off (source none), so nothing here needs the network.
const logo = fileURLToPath(new URL('../public/logo.svg', import.meta.url))

test.describe.serial('M7: appearance, application icons and the launcher', () => {
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

  test('the appearance page sets the sign-in title', async ({ browser }) => {
    await page.goto('/admin/i/appearance')
    await expect(page.getByRole('heading', { name: 'Appearance', level: 1 })).toBeVisible()
    await expect(page.getByText('No image providers: backgrounds are off.')).toBeVisible()
    await expect(page.getByText('Backgrounds are off: add an image provider.')).toBeVisible()
    await expectAccessible(page)
    // Providers explain themselves and can be reordered and removed (not saved here: that would need the network).
    await page.getByRole('button', { name: 'Add Wikimedia Commons' }).click()
    await page.getByRole('button', { name: 'Add image URLs' }).click()
    const first = page.getByRole('region', { name: 'Provider 1: Wikimedia Commons' })
    await expect(first.getByRole('textbox', { name: 'Category' })).toHaveValue('Featured pictures of landscapes')
    await expect(page.getByRole('region', { name: 'Provider 2: Your own images' })).toBeVisible()
    await settle(page)
    await expectAccessible(page)
    await page.getByRole('button', { name: 'Move Provider 2 up' }).click()
    await expect(page.getByRole('region', { name: 'Provider 1: Your own images' })).toBeVisible()
    await page.getByRole('button', { name: 'Remove Provider 1' }).click()
    await page.getByRole('button', { name: 'Remove Provider 1' }).click()
    await expect(page.getByText('No image providers: backgrounds are off.')).toBeVisible()
    await page.getByRole('textbox', { name: 'Title' }).fill('Smith family')
    await page.getByRole('button', { name: 'Save appearance' }).click()
    await expect(page.getByText('Appearance saved')).toBeVisible()

    const anon = await browser.newContext()
    const p = await anon.newPage()
    await p.goto('/login')
    await expect(p.getByRole('heading', { name: 'Welcome to Smith family' })).toBeVisible()
    await settle(p)
    await expectAccessible(p)
    await anon.close()
  })

  test('an uploaded SVG icon and a group show up on the launcher', async ({ browser }) => {
    await page.goto('/admin/t/smith/applications')
    await page.getByRole('button', { name: 'Manage Whoami' }).click()
    const drawer = page.getByRole('dialog', { name: 'Whoami' })
    await drawer.getByRole('textbox', { name: 'Launcher group' }).fill('Tools')
    await drawer.getByRole('textbox', { name: 'Icon', exact: true }).click()
    await page.getByRole('option', { name: 'Upload an image' }).click()
    await drawer.locator('input[type="file"]').setInputFiles(logo)
    await expect(drawer.getByRole('img', { name: 'Icon preview' })).toBeVisible()
    await settle(page)
    await expectAccessible(page)
    await drawer.getByRole('button', { name: 'Save launcher settings' }).click()
    await expect(page.getByText('Launcher settings saved')).toBeVisible()
    await expect(drawer.getByRole('img', { name: 'Icon preview' })).toHaveAttribute('src', /^\/media\/[0-9a-f]{64}$/)

    const ada = await browser.newContext()
    const p = await ada.newPage()
    await googleLogin(p, 'Ada Smith')
    await expect(p.getByRole('heading', { name: 'My applications' })).toBeVisible()
    const tools = p.getByRole('region', { name: 'Tools' })
    const tile = tools.getByRole('article', { name: 'Whoami' })
    await expect(tile.locator('img')).toHaveAttribute('src', /^\/media\//)
    expect(await tile.locator('img').evaluate((img: HTMLImageElement) => img.naturalWidth)).toBeGreaterThan(0)
    // Search filters across sections.
    await p.getByRole('textbox', { name: 'Search applications' }).fill('who')
    await expect(p.getByRole('article', { name: 'Whoami' })).toBeVisible()
    await expect(p.getByRole('article', { name: 'Demo app' })).toHaveCount(0)
    await p.getByRole('textbox', { name: 'Search applications' }).fill('nothing-like-this')
    await expect(p.getByText('No application matches')).toBeVisible()
    await p.getByRole('textbox', { name: 'Search applications' }).fill('')
    await expect(p.getByRole('article', { name: 'Demo app' })).toBeVisible()
    await settle(p)
    await expectAccessible(p)
    await ada.close()
  })
})
