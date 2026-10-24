import { Badge, Button, Card, Group, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useMemo, useState, type SyntheticEvent } from 'react'
import { useAdminMutation } from '@/api/admin'
import { allTenantsQuery, installKeys, sessionsQuery, userQuery, type AdminSession } from '@/api/admin/install'
import { api, check } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { sessionsSearch } from '@/components/admin/install/search'
import { ConfirmAction } from '@/components/admin/install/ConfirmAction'
import { DateTime, Loading, Notice, RefreshButton } from '@/components/admin/install/ui'

export const Route = createFileRoute('/_app/admin/i/sessions')({
  validateSearch: sessionsSearch,
  component: Sessions,
})

function Sessions() {
  const { user } = Route.useSearch()
  return <SessionsPage key={user ?? ''} user={user} />
}

function SessionsPage({ user }: { user: string | undefined }) {
  const navigate = useNavigate({ from: '/admin/i/sessions' })
  const q = useQuery(sessionsQuery(user))
  const tenants = useQuery(allTenantsQuery)
  const filterUser = useQuery(userQuery(user ?? ''))
  const tenantNames = useMemo(() => new Map((tenants.data ?? []).map((t) => [t.id, t.name])), [tenants.data])
  const [draft, setDraft] = useState(user ?? '')
  const apply = (e: SyntheticEvent) => {
    e.preventDefault()
    const v = draft.trim()
    void navigate({ search: v ? { user: v } : {} })
  }
  const userName = filterUser.data?.display_name ?? q.data?.[0]?.user_name
  return (
    <Stack>
      <PageHeader
        title="Sessions"
        description="Browsers currently signed in to Porch across the installation, most recently active first."
        actions={<RefreshButton onClick={() => q.refetch()} loading={q.isRefetching} />}
      />
      <Card component="form" onSubmit={apply} padding="md" aria-label="Filter sessions">
        <Group align="flex-end" wrap="wrap">
          <TextInput
            label="User ID"
            description="Show only this user's sessions"
            value={draft}
            onChange={(e) => {
              setDraft(e.currentTarget.value)
            }}
            style={{ flex: '1 1 280px' }}
          />
          <Button type="submit">Filter</Button>
          {user ? (
            <Button
              variant="default"
              onClick={() => {
                setDraft('')
                void navigate({ search: {} })
              }}
            >
              Show all sessions
            </Button>
          ) : null}
        </Group>
      </Card>
      {user ? <Notice tone="info">Showing sessions of {userName ? `${userName} (${user})` : user}.</Notice> : null}
      <ErrorAlert error={q.error} title="Could not load sessions" />
      {q.isPending ? <Loading label="Loading sessions…" /> : null}
      {q.data?.length === 0 ? (
        <EmptyState>{user ? 'This user has no active sessions.' : 'No active sessions.'}</EmptyState>
      ) : null}
      {q.data?.length ? (
        <Table.ScrollContainer minWidth={1100}>
          <Table striped highlightOnHover aria-label="Active sessions" verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>User</Table.Th>
                <Table.Th>Method</Table.Th>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>IP address</Table.Th>
                <Table.Th>Browser</Table.Th>
                <Table.Th>Created</Table.Th>
                <Table.Th>Last seen</Table.Th>
                <Table.Th>Expires</Table.Th>
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {q.data.map((s) => (
                <SessionRow key={s.id} s={s} tenantName={s.tenant_id ? tenantNames.get(s.tenant_id) : undefined} />
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : null}
    </Stack>
  )
}

function SessionRow({ s, tenantName }: { s: AdminSession; tenantName?: string }) {
  const revoke = useAdminMutation({
    mutationFn: async () => {
      check(await api.DELETE('/sessions/{session}', { params: { path: { session: s.id } } }))
    },
    success: s.current ? 'Your session was ended' : `Session of ${s.user_name} ended`,
    invalidate: s.current ? [] : [installKeys.sessions, installKeys.health],
    onSuccess: () => {
      if (s.current) window.location.assign('/login')
    },
  })
  return (
    <Table.Tr>
      <Table.Td>
        <Group gap={6} wrap="nowrap">
          <Text size="sm" fw={500}>
            {s.user_name}
          </Text>
          {s.current ? (
            <Badge variant="default" size="sm" tt="none">
              this session
            </Badge>
          ) : null}
        </Group>
        <Text size="xs" c="dimmed">
          {s.user_email ?? s.user_id}
        </Text>
      </Table.Td>
      <Table.Td>{s.method}</Table.Td>
      <Table.Td>{s.tenant_id ? (tenantName ?? s.tenant_id) : '—'}</Table.Td>
      <Table.Td>{s.ip ?? '—'}</Table.Td>
      <Table.Td maw={260}>
        <Text size="xs" lineClamp={2} title={s.user_agent}>
          {s.user_agent ?? '—'}
        </Text>
      </Table.Td>
      <Table.Td>
        <DateTime value={s.created_at} />
      </Table.Td>
      <Table.Td>
        <DateTime value={s.last_seen_at} />
      </Table.Td>
      <Table.Td>
        <DateTime value={s.expires_at} />
      </Table.Td>
      <Table.Td>
        <ConfirmAction
          label={
            <>
              Revoke<VisuallyHidden> session of {s.user_name}</VisuallyHidden>
            </>
          }
          confirmLabel={s.current ? 'Sign me out' : 'Revoke session'}
          title={s.current ? 'End your own session?' : `End this session of ${s.user_name}?`}
          loading={revoke.isPending}
          onConfirm={() => revoke.mutateAsync(undefined).catch(() => undefined)}
        >
          {s.current ? (
            <Notice tone="warning" title="This is your current session">
              You will be signed out of this browser immediately.
            </Notice>
          ) : (
            <Text size="sm">
              {s.user_name} is signed out of this browser immediately ({s.ip ?? 'unknown address'}, signed in with{' '}
              {s.method}).
            </Text>
          )}
        </ConfirmAction>
      </Table.Td>
    </Table.Tr>
  )
}
