import { Badge, type BadgeProps } from '@mantine/core'
import {
  IconAlertTriangle,
  IconCircleCheck,
  IconCircleMinus,
  IconCircleX,
  IconInfoCircle,
  type Icon,
} from '@tabler/icons-react'

export type Tone = 'ok' | 'warning' | 'critical' | 'info' | 'neutral'

export const tones: Record<Tone, { icon: Icon; color: string }> = {
  ok: { icon: IconCircleCheck, color: 'green' },
  warning: { icon: IconAlertTriangle, color: 'yellow' },
  critical: { icon: IconCircleX, color: 'red' },
  info: { icon: IconInfoCircle, color: 'blue' },
  neutral: { icon: IconCircleMinus, color: 'gray' },
}

/**
 * A status badge that carries its meaning in text and icon; the colour only reinforces it. The label keeps the theme's
 * text colour so it meets contrast requirements in light and dark mode.
 */
export function StatusBadge({
  tone,
  children,
  size = 'md',
}: {
  tone: Tone
  children: string
  size?: BadgeProps['size']
}) {
  const { icon: I, color } = tones[tone]
  return (
    <Badge
      variant="default"
      size={size}
      tt="none"
      fw={600}
      leftSection={<I size={14} aria-hidden stroke={2} color={`var(--mantine-color-${color}-filled)`} />}
    >
      {children}
    </Badge>
  )
}

/** Maps API status words to tones. */
export function toneOf(status: string): Tone {
  switch (status) {
    case 'ok':
    case 'active':
    case 'success':
      return 'ok'
    case 'warning':
    case 'degraded':
    case 'retiring':
    case 'denied':
      return 'warning'
    case 'critical':
    case 'failed':
    case 'failure':
      return 'critical'
    case 'info':
      return 'info'
    default:
      return 'neutral'
  }
}
