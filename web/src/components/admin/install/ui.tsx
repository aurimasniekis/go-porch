import { Alert, Button, Group, Loader, Text, type MantineSpacing } from '@mantine/core'
import { IconRefresh } from '@tabler/icons-react'
import type { ReactNode } from 'react'
import { tones, type Tone } from './StatusBadge'

/**
 * A callout whose meaning is carried by its title, text and icon. It uses the neutral "default" variant so the text keeps
 * the theme's text colour (Mantine's tinted variants fail WCAG AA contrast for yellow/green/red/gray titles).
 */
export function Notice({
  tone,
  title,
  children,
  mt,
  live,
}: {
  tone: Tone
  title?: string
  children: ReactNode
  mt?: MantineSpacing
  /** status: polite announcement; alert: assertive; none: static information. */
  live?: 'status' | 'alert' | 'none'
}) {
  const { icon: I, color } = tones[tone]
  return (
    <Alert
      variant="default"
      title={title}
      mt={mt}
      role={live === 'none' || !live ? 'note' : live}
      icon={<I size={18} aria-hidden stroke={2} color={`var(--mantine-color-${color}-filled)`} />}
    >
      {children}
    </Alert>
  )
}

/** A polite loading indicator. */
export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <Group justify="center" py="xl" gap="xs" role="status">
      <Loader size="sm" />
      <Text size="sm" c="dimmed">
        {label}
      </Text>
    </Group>
  )
}

/** A refresh button that spins while the data is being refetched. */
export function RefreshButton({
  onClick,
  loading,
  label = 'Refresh',
}: {
  onClick: () => unknown
  loading?: boolean
  label?: string
}) {
  return (
    <Button
      variant="default"
      size="sm"
      leftSection={<IconRefresh size={16} aria-hidden />}
      loading={loading}
      onClick={() => void onClick()}
    >
      {label}
    </Button>
  )
}

/** A date-time rendered in the viewer's locale with a machine-readable value. */
export function DateTime({ value }: { value: string | undefined | null }) {
  if (!value) return <>—</>
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return <>—</>
  return <time dateTime={value}>{d.toLocaleString()}</time>
}
