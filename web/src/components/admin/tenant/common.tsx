import {
  ActionIcon,
  Alert,
  Badge,
  Button,
  Code,
  CopyButton,
  Group,
  Skeleton,
  Stack,
  Text,
  Tooltip,
  type AlertProps,
  type BadgeProps,
} from '@mantine/core'
import { IconCheck, IconCopy, IconRefresh } from '@tabler/icons-react'
import type { ReactNode } from 'react'
import { isConflict } from '@/api/admin/tenant'
import { ErrorAlert } from '@/components/admin/kit'

/** A copyable value with a visible label (secrets, client IDs, URLs). */
export function CopyField({ label, value, secret }: { label: string; value: string; secret?: boolean }) {
  return (
    <Stack gap={2}>
      <Text size="sm" fw={500}>
        {label}
      </Text>
      <Group gap="xs" wrap="nowrap" align="center">
        <Code
          block={secret}
          style={{ flex: 1, minWidth: 0, overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}
          data-testid={`copy-${label}`}
        >
          {value}
        </Code>
        <CopyButton value={value} timeout={1500}>
          {({ copied, copy }) => (
            <Tooltip label={copied ? 'Copied' : 'Copy'} withArrow>
              <ActionIcon
                variant="subtle"
                color={copied ? 'teal' : 'gray'}
                onClick={copy}
                aria-label={`Copy ${label.toLowerCase()}`}
              >
                {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
              </ActionIcon>
            </Tooltip>
          )}
        </CopyButton>
      </Group>
    </Stack>
  )
}

/**
 * Shows a failed mutation. A 412 (someone else changed the resource) offers to reload the latest version; other
 * errors use the shared ErrorAlert.
 */
export function MutationError({ error, onReload }: { error: unknown; onReload?: () => unknown }) {
  if (!error) return null
  if (isConflict(error)) {
    return (
      <Notice color="orange" title="Changed by someone else" role="alert">
        <Stack gap="xs" align="flex-start">
          <Text size="sm">{error instanceof Error ? error.message : ''}</Text>
          {onReload ? (
            <Button size="xs" variant="default" leftSection={<IconRefresh size={14} />} onClick={() => void onReload()}>
              Reload latest version
            </Button>
          ) : null}
        </Stack>
      </Notice>
    )
  }
  return <ErrorAlert error={error} title="Not saved" />
}

/** Placeholder rows while a list loads. */
export function LoadingRows({ rows = 3 }: { rows?: number }) {
  return (
    <Stack gap="xs" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} height={36} radius="sm" />
      ))}
    </Stack>
  )
}

/** A titled section of a page. */
export function Section({
  title,
  description,
  actions,
  children,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  return (
    <Stack gap="sm">
      <Group justify="space-between" align="flex-end" wrap="wrap">
        <Stack gap={2}>
          <Text component="h2" fw={600} size="lg" m={0}>
            {title}
          </Text>
          {description ? (
            <Text size="sm" c="dimmed" maw={720}>
              {description}
            </Text>
          ) : null}
        </Stack>
        {actions ? <Group gap="xs">{actions}</Group> : null}
      </Group>
      {children}
    </Stack>
  )
}

/** A light badge (contrast-safe colours come from the theme, ADR-0040). */
export function Tag(props: BadgeProps & { children: ReactNode }) {
  return <Badge variant="light" {...props} />
}

/** An alert (kept as a name for the pages that use it). */
export function Notice(props: AlertProps) {
  return <Alert {...props} />
}

/** Who manages a resource. */
export { Provenance as ProvenanceTag } from '@/components/admin/kit'
