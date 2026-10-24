import { createTheme, type CSSVariablesResolver, type MantineColorsTuple } from '@mantine/core'

const porch: MantineColorsTuple = [
  '#eaf1ff',
  '#d3e0fb',
  '#a6bef0',
  '#769ae6',
  '#4f7cdd',
  '#3769d8',
  '#295fd7',
  '#1b4fbf',
  '#1246ab',
  '#003b97',
]

export const theme = createTheme({
  primaryColor: 'porch',
  primaryShade: { light: 6, dark: 4 },
  autoContrast: true,
  luminanceThreshold: 0.25,
  colors: { porch },
  fontFamily: "'Inter Variable', Inter, system-ui, -apple-system, 'Segoe UI', sans-serif",
  headings: { fontFamily: "'Inter Variable', Inter, system-ui, sans-serif", fontWeight: '600' },
  defaultRadius: 'md',
  cursorType: 'pointer',
  components: {
    Card: { defaultProps: { withBorder: true, padding: 'lg', radius: 'md' } },
    // Close buttons need an accessible name (axe button-name).
    // Scroll lock (react-remove-scroll) injects a <style> without the CSP nonce, so it stays off.
    Modal: { defaultProps: { closeButtonProps: { 'aria-label': 'Close' }, lockScroll: false } },
    Drawer: { defaultProps: { closeButtonProps: { 'aria-label': 'Close' }, lockScroll: false } },
    Notification: { defaultProps: { closeButtonProps: { 'aria-label': 'Close notification' } } },
  },
})

/**
 * Text colour of the `light` and `outline` variants (badges, alerts, buttons) in the light scheme. Mantine uses shade 6, which
 * fails WCAG AA on the variant's own tint; these values reach at least 4.6:1 on the tint over white and over striped
 * table rows (computed, see docs/DECISIONS.md ADR-0040).
 */
const lightVariantText: Record<string, string> = {
  porch: '#003b97',
  blue: '#1864ab',
  cyan: '#0b7082',
  grape: '#862e9c',
  green: '#247434',
  indigo: '#364fc7',
  lime: '#48730a',
  orange: '#b63c0d',
  pink: '#a61e4d',
  red: '#bd2727',
  teal: '#077554',
  violet: '#5f3dc4',
  yellow: '#a15300',
  gray: '#212529',
}

/** Mantine's default dimmed grey (#868e96) and error red (#fa5252) fail WCAG AA contrast on white. */
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: {
    '--mantine-color-dimmed': 'var(--mantine-color-gray-7)',
    '--mantine-color-error': 'var(--mantine-color-red-9)',
    ...Object.fromEntries(Object.entries(lightVariantText).map(([c, v]) => [`--mantine-color-${c}-light-color`, v])),
    // Outline badges and buttons draw text (and border) in the same colour on white.
    ...Object.fromEntries(Object.entries(lightVariantText).map(([c, v]) => [`--mantine-color-${c}-outline`, v])),
  },
  dark: { '--mantine-color-dimmed': 'var(--mantine-color-dark-1)' },
})
