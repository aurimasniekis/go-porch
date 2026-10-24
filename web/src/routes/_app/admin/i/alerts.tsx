import { Anchor, Button, Card, Group, Stack, Text, Title, VisuallyHidden } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { adminQuery, useAdminMutation } from '@/api/admin'
import { alertsQuery, installKeys, userQuery, type Alert } from '@/api/admin/install'
import { api, check } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { StatusBadge, toneOf } from '@/components/admin/install/StatusBadge'
import { ConfirmAction } from '@/components/admin/install/ConfirmAction'
import { DateTime, Loading, RefreshButton } from '@/components/admin/install/ui'

export const Route = createFileRoute('/_app/admin/i/alerts')({
  component: Alerts,
})

/** Human titles for alert kinds. */
const kindTitles: Record<string, string> = {
  recovery_link_used: 'Offline recovery link used',
}

/** Alert kinds whose target is a user. */
const userKinds = new Set(['recovery_link_used'])

function Alerts() {
  const q = useQuery(alertsQuery)
  const caps = useQuery(adminQuery)
  const canAct = !!caps.data?.installation
  return (
    <Stack>
      <PageHeader
        title="Alerts"
        description="Security events that need an operator's attention. Alerts stay open until someone acknowledges them."
        actions={<RefreshButton onClick={() => q.refetch()} loading={q.isRefetching} />}
      />
      <ErrorAlert error={q.error} title="Could not load alerts" />
      {q.isPending ? <Loading label="Loading alerts…" /> : null}
      {q.data?.length === 0 ? <EmptyState>No open alerts. All clear.</EmptyState> : null}
      {q.data?.length ? (
        <Stack component="ul" gap="sm" p={0} m={0} style={{ listStyle: 'none' }} aria-label="Open alerts">
          {q.data.map((a) => (
            <AlertItem key={a.id} a={a} canAct={canAct} />
          ))}
        </Stack>
      ) : null}
    </Stack>
  )
}

function AlertItem({ a, canAct }: { a: Alert; canAct: boolean }) {
  const isUser = !!a.target_id && userKinds.has(a.kind)
  const user = useQuery({ ...userQuery(isUser ? (a.target_id ?? '') : ''), retry: false })
  const title = kindTitles[a.kind] ?? a.kind
  const ack = useAdminMutation({
    mutationFn: async () => {
      check(await api.POST('/installation/alerts/{alert}/ack', { params: { path: { alert: a.id } } }))
    },
    success: 'Alert acknowledged',
    invalidate: [installKeys.alerts, installKeys.health],
  })
  const endSessions = useAdminMutation({
    mutationFn: async () => {
      check(await api.POST('/users/{user}/revoke-sessions', { params: { path: { user: a.target_id ?? '' } } }))
    },
    success: 'All sessions of the user ended',
    invalidate: [installKeys.sessions, installKeys.health],
  })
  const who = user.data?.display_name ?? a.target_id
  return (
    <Card component="li">
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Stack gap={4} style={{ flex: '1 1 320px' }}>
          <Group gap="xs">
            <StatusBadge tone={toneOf(a.severity)}>{a.severity}</StatusBadge>
            <Title order={2} size="h5">
              {title}
            </Title>
          </Group>
          <Text size="sm">{a.message}</Text>
          <Text size="xs" c="dimmed">
            Raised <DateTime value={a.created_at} />
            {a.target_id ? ` · ${isUser ? 'User' : 'Target'}: ${who ?? ''}` : ''}
          </Text>
          {a.target_id ? (
            <Group gap="md" mt={4}>
              <Anchor
                size="sm"
                renderRoot={(props) => <Link {...props} to="/admin/i/audit" search={{ actor: a.target_id }} />}
              >
                Audit events by this {isUser ? 'user' : 'actor'}
              </Anchor>
              {isUser ? (
                <Anchor
                  size="sm"
                  renderRoot={(props) => <Link {...props} to="/admin/i/sessions" search={{ user: a.target_id }} />}
                >
                  Their sessions
                </Anchor>
              ) : null}
            </Group>
          ) : null}
        </Stack>
        {canAct ? (
          <Group gap="xs">
            {isUser ? (
              <ConfirmAction
                label={
                  <>
                    End all sessions<VisuallyHidden> of {who}</VisuallyHidden>
                  </>
                }
                confirmLabel="End all sessions"
                title={`End all sessions of ${who ?? 'this user'}?`}
                loading={endSessions.isPending}
                onConfirm={() => endSessions.mutateAsync(undefined).catch(() => undefined)}
              >
                <Text size="sm">
                  If you did not expect this sign-in, end every session of the user now. This needs a recent sign-in.
                </Text>
              </ConfirmAction>
            ) : null}
            <Button
              size="xs"
              loading={ack.isPending}
              onClick={() => {
                ack.mutate(undefined)
              }}
            >
              Acknowledge<VisuallyHidden> {title}</VisuallyHidden>
            </Button>
          </Group>
        ) : null}
      </Group>
    </Card>
  )
}
