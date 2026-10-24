import { Alert, Badge, Code, Group, Loader, Text, Tooltip } from '@mantine/core'
import { IconCheck, IconShieldX, IconX } from '@tabler/icons-react'
import type { ReactNode } from 'react'
import { isEscalation, missingPermissions } from '@/api/admin/authz'
import { ErrorAlert } from '@/components/admin/kit'

/**
 * Alert titles in the body text colour: the light variant's green/teal/cyan title text stays below WCAG AA contrast
 * even with the theme's darker light-colour shades; the coloured frame and icon still carry the tone.
 */
export const alertTitleStyles = { title: { color: 'var(--mantine-color-text)' } }

/** Shown while a page's data loads. */
export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <Group justify="center" py="xl" role="status" aria-live="polite">
      <Loader size="sm" aria-hidden />
      <Text c="dimmed" size="sm">
        {label}
      </Text>
    </Group>
  )
}

/**
 * A failed change inside a form. Privilege-escalation refusals (a delegated administrator granting what they do not
 * hold) get their own explanation listing the missing permissions.
 */
export function MutationError({ error }: { error: unknown }) {
  if (!error) return null
  if (isEscalation(error)) {
    const missing = missingPermissions(error)
    return (
      <Alert
        color="red"
        icon={<IconShieldX size={18} />}
        title="Privilege escalation refused"
        role="alert"
        styles={alertTitleStyles}
      >
        <Text size="sm">
          You can only grant permissions that you hold yourself, unconditionally, across the whole tenant.
        </Text>
        {missing.length > 0 ? (
          <Group gap={6} mt="xs">
            <Text size="sm">Not held by you:</Text>
            {missing.map((p) => (
              <Code key={p}>{p}</Code>
            ))}
          </Group>
        ) : null}
      </Alert>
    )
  }
  return <ErrorAlert error={error} title="Not saved" />
}

/** A permission rendered as code. */
export function Perm({ children }: { children: ReactNode }) {
  return <Code>{children}</Code>
}

/** Small yes/no marker with a text alternative. */
export function YesNo({ value, yes = 'yes', no = 'no' }: { value: boolean; yes?: string; no?: string }) {
  return (
    <Group gap={4} wrap="nowrap">
      {value ? (
        <IconCheck size={16} aria-hidden color="var(--mantine-color-green-filled)" />
      ) : (
        <IconX size={16} aria-hidden color="var(--mantine-color-red-filled)" />
      )}
      <Text size="sm">{value ? yes : no}</Text>
    </Group>
  )
}

/** A badge readable in both colour schemes (filled variants get automatic text contrast from the theme). */
export function Tag({ color, children }: { color: string; children: ReactNode }) {
  return (
    <Badge color={color} variant="filled" size="sm" tt="none">
      {children}
    </Badge>
  )
}

const managedColors: Record<string, string> = { terraform: 'violet', api: 'cyan', ui: 'gray', system: 'teal' }

/**
 * Who manages an object (informational). Same meaning as the kit's Provenance, drawn with filled badges because the
 * light teal/cyan badges stay below WCAG AA contrast.
 */
export function ManagedBy({ managedBy }: { managedBy?: string }) {
  if (!managedBy) return null
  const badge = <Tag color={managedColors[managedBy] ?? 'gray'}>{managedBy}</Tag>
  if (managedBy !== 'terraform') return badge
  return (
    <Tooltip label="Managed by Terraform: manual changes are overwritten on the next apply.">
      <span>{badge}</span>
    </Tooltip>
  )
}
