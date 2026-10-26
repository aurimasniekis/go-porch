import { Button, Card, Group, Select, Stack, Table, Text } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, useAdminMutation } from '@/api/admin'
import { installKeys, operatorsQuery } from '@/api/admin/install'
import { api, check, unwrap } from '@/api/client'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { StatusBadge } from '@/components/admin/install/StatusBadge'
import { DateTime, Loading } from '@/components/admin/install/ui'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/i/operators')({
  component: Operators,
})

const roleInfo: Record<string, string> = {
  owner: 'Full control, including key rotation',
  admin: 'Manages tenants, users, providers and sessions',
  auditor: 'Reads installation health, alerts, backups and the audit log',
  inspector: 'Reads the configuration of every tenant; changes nothing',
}

type Role = 'owner' | 'admin' | 'auditor' | 'inspector'

function GrantRole() {
  const users = useQuery({
    queryKey: [...installKeys.users, 'picker'],
    queryFn: async () => unwrap(await api.GET('/users', { params: { query: { limit: 200 } } })),
  })
  const [user, setUser] = useState<string | null>(null)
  const [role, setRole] = useState<Role>('admin')
  const grant = useAdminMutation({
    mutationFn: async (v: { user_id: string; role: Role }) => {
      check(await api.POST('/installation/operators', { body: v }))
    },
    success: 'Role granted',
    invalidate: [['install', 'operators']],
    onSuccess: () => {
      setUser(null)
    },
  })
  return (
    <Card
      padding="md"
      component="form"
      aria-label="Grant an installation role"
      onSubmit={(e) => {
        e.preventDefault()
        if (user) grant.mutate({ user_id: user, role })
      }}
    >
      <Group align="flex-end" wrap="wrap">
        <Select
          label="User"
          placeholder="Choose a user"
          searchable
          data={(users.data?.items ?? []).map((u) => ({
            value: u.id,
            label: u.primary_email ? `${u.display_name} (${u.primary_email})` : u.display_name,
          }))}
          value={user}
          onChange={setUser}
          style={{ flex: '1 1 280px' }}
        />
        <Select
          label="Role"
          data={[
            { value: 'admin', label: 'Admin' },
            { value: 'auditor', label: 'Auditor' },
            { value: 'inspector', label: 'Inspector' },
            { value: 'owner', label: 'Owner' },
          ]}
          value={role}
          allowDeselect={false}
          onChange={(v) => {
            if (v) setRole(v as Role)
          }}
          w={160}
        />
        <Button type="submit" disabled={!user} loading={grant.isPending}>
          Grant role
        </Button>
      </Group>
      <Text size="xs" c="dimmed" mt="xs">
        Granting or removing installation roles needs a recent sign-in.
      </Text>
    </Card>
  )
}

function Operators() {
  const q = useQuery(operatorsQuery)
  const caps = useQuery(adminQuery)
  const isOwner = caps.data?.operator_roles.includes('owner') ?? false
  const revoke = useAdminMutation({
    mutationFn: async (v: { user: string; role: Role }) => {
      check(await api.DELETE('/installation/operators/{user}/{role}', { params: { path: v } }))
    },
    success: 'Role removed',
    invalidate: [['install', 'operators']],
  })
  return (
    <Stack>
      <PageHeader
        title="Operators"
        description={
          isOwner
            ? 'Users with installation-wide roles. Only owners can grant or remove them; the last owner cannot be removed.'
            : 'Users with installation-wide roles. Only owners can change them.'
        }
      />
      {isOwner ? <GrantRole /> : null}
      <ErrorAlert error={q.error} title="Could not load operators" />
      {q.isPending ? <Loading label="Loading operators…" /> : null}
      {q.data?.length === 0 ? <EmptyState>No operators.</EmptyState> : null}
      {q.data?.length ? (
        <ListTable minWidth={720} striped aria-label="Installation operators" verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>User</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>Granted by</Table.Th>
              <Table.Th>Since</Table.Th>
              {isOwner ? <Table.Th>Actions</Table.Th> : null}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data.map((o) => (
              <Table.Tr key={`${o.user_id}:${o.role}`}>
                <Table.Td>
                  <Text size="sm" fw={500}>
                    {o.display_name}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {o.email ?? o.user_id}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <StatusBadge tone="info">{o.role}</StatusBadge>
                  {roleInfo[o.role] ? (
                    <Text size="xs" c="dimmed" mt={4}>
                      {roleInfo[o.role]}
                    </Text>
                  ) : null}
                </Table.Td>
                <Table.Td>{o.source}</Table.Td>
                <Table.Td>
                  <DateTime value={o.created_at} />
                </Table.Td>
                {isOwner ? (
                  <Table.Td>
                    <ConfirmButton
                      label="Remove"
                      title={`Remove the ${o.role} role?`}
                      loading={revoke.isPending}
                      onConfirm={() => revoke.mutateAsync({ user: o.user_id, role: o.role as Role })}
                    >
                      {o.display_name} loses the installation {o.role} role immediately.
                    </ConfirmButton>
                  </Table.Td>
                ) : null}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ListTable>
      ) : null}
    </Stack>
  )
}
