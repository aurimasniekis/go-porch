import { Alert, Badge, Button, Group, Modal, Stack, Text, Title, Tooltip } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconAlertTriangle, IconEye, IconLock } from '@tabler/icons-react'
import type { ReactNode } from 'react'
import { actionUrl, ApiError } from '@/api/client'

/** Page title, one-line description and actions. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
}) {
  return (
    <Group justify="space-between" align="flex-start" mb="md" wrap="wrap">
      <Stack gap={4}>
        <Title order={1} size="h2">
          {title}
        </Title>
        {description ? (
          <Text c="dimmed" size="sm" maw={720}>
            {description}
          </Text>
        ) : null}
      </Stack>
      {actions ? <Group gap="xs">{actions}</Group> : null}
    </Group>
  )
}

/** Shows a failed query or mutation; a step-up problem offers the re-authentication link. */
export function ErrorAlert({ error, title = 'Something went wrong' }: { error: unknown; title?: string }) {
  if (!error) return null
  const e = error instanceof ApiError ? error : null
  if (e?.code === 'reauth_required' && e.action) {
    return (
      <Alert color="yellow" icon={<IconLock size={18} />} title="Confirm it's you">
        This action needs a recent sign-in.{' '}
        <Button component="a" href={actionUrl(e.action)} size="xs" variant="light" ml="xs">
          Sign in again
        </Button>
      </Alert>
    )
  }
  return (
    <Alert color="red" icon={<IconAlertTriangle size={18} />} title={title} role="alert">
      {error instanceof Error ? error.message : 'Unexpected error'}
    </Alert>
  )
}

/** A button that asks for confirmation before running a destructive action. */
export function ConfirmButton({
  label,
  title,
  children,
  onConfirm,
  loading,
  color = 'red',
  confirmLabel,
  variant = 'light',
  size = 'xs',
  disabled,
}: {
  label: ReactNode
  title: string
  children: ReactNode
  onConfirm: () => unknown
  loading?: boolean
  color?: string
  confirmLabel?: string
  variant?: string
  size?: string
  disabled?: boolean
}) {
  const [opened, { open, close }] = useDisclosure(false)
  return (
    <>
      <Button color={color} variant={variant} size={size} onClick={open} disabled={disabled}>
        {label}
      </Button>
      <Modal opened={opened} onClose={close} title={title} centered>
        <Stack>
          <div>{children}</div>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button
              color={color}
              loading={loading}
              onClick={() => {
                void (async () => {
                  try {
                    await onConfirm()
                  } finally {
                    close()
                  }
                })()
              }}
            >
              {confirmLabel ?? (typeof label === 'string' ? label : 'Confirm')}
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  )
}

const managedColors: Record<string, string> = { terraform: 'violet', api: 'blue', ui: 'gray', system: 'teal' }

/** Who manages a resource (informational; Terraform-managed resources may be overwritten on the next apply). */
export function Provenance({ managedBy, lastChangedBy }: { managedBy?: string; lastChangedBy?: string }) {
  if (!managedBy) return null
  const badge = (
    <Badge variant="light" color={managedColors[managedBy] ?? 'gray'} size="sm">
      {managedBy}
    </Badge>
  )
  if (managedBy !== 'terraform' && !lastChangedBy) return badge
  return (
    <Tooltip
      label={[
        managedBy === 'terraform' ? 'Managed by Terraform: manual changes are overwritten on the next apply.' : null,
        lastChangedBy ? `Last changed by ${lastChangedBy}` : null,
      ]
        .filter(Boolean)
        .join(' ')}
    >
      {badge}
    </Tooltip>
  )
}

/**
 * Says a page is shown read-only because the caller may view but not change it (read permissions and installation
 * inspectors, ADR-0048). `what` completes "you can view but not change …".
 */
export function ReadOnlyNote({ what, mb = 'md' }: { what: ReactNode; mb?: string | number }) {
  return (
    <Group gap={6} wrap="nowrap" mb={mb} data-testid="read-only-note">
      <IconEye size={16} aria-hidden color="var(--mantine-color-dimmed)" style={{ flexShrink: 0 }} />
      <Text size="sm" c="dimmed">
        Read-only: you can view but not change {what}.
      </Text>
    </Group>
  )
}

/** Shown when a list is empty. */
export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <Text c="dimmed" ta="center" py="xl">
      {children}
    </Text>
  )
}

/** Placeholder for a section that is not built yet. */
export function Placeholder({ title }: { title: string }) {
  return <PageHeader title={title} description="This section is being built." />
}
