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
  },
})

/** Mantine's default dimmed grey (#868e96) fails WCAG AA contrast on white; use darker/lighter greys. */
export const cssVariablesResolver: CSSVariablesResolver = () => ({
  variables: {},
  light: { '--mantine-color-dimmed': 'var(--mantine-color-gray-7)' },
  dark: { '--mantine-color-dimmed': 'var(--mantine-color-dark-1)' },
})
