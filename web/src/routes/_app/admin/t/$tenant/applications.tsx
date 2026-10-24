import { Button, Drawer, Group, Stack, Table, Text, VisuallyHidden } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { applicationsQuery, type Application } from '@/api/admin/tenant'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { AppCreateModal } from '@/components/admin/tenant/AppCreateModal'
import { AppDetail } from '@/components/admin/tenant/AppDetail'
import { LoadingRows, ProvenanceTag, Tag } from '@/components/admin/tenant/common'
import { SecretModal, type OneTimeSecret } from '@/components/admin/tenant/SecretModal'

export const Route = createFileRoute('/_app/admin/t/$tenant/applications')({
  validateSearch: (s: Record<string, unknown>): { app?: string } =>
    typeof s.app === 'string' && s.app ? { app: s.app } : {},
  component: ApplicationsPage,
})

function ApplicationsPage() {
  const { tenant } = Route.useParams()
  const { app } = Route.useSearch()
  const navigate = useNavigate({ from: Route.fullPath })
  const q = useQuery(applicationsQuery(tenant))
  const [creating, { open: openCreate, close: closeCreate }] = useDisclosure(false)
  const [secret, setSecret] = useState<OneTimeSecret | null>(null)
  const select = (id: string | undefined) => void navigate({ search: id ? { app: id } : {} })
  const current = q.data?.find((a) => a.id === app)
  return (
    <Stack gap="lg">
      <PageHeader
        title="Applications"
        description="Applications people sign in to through Porch: OpenID Connect clients and services behind a forward-auth reverse proxy."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={openCreate}>
            New application
          </Button>
        }
      />
      {q.error ? <ErrorAlert error={q.error} /> : null}
      {q.isPending ? (
        <LoadingRows />
      ) : !q.data?.length ? (
        q.error ? null : (
          <EmptyState>No applications yet. Create one to let members sign in to it.</EmptyState>
        )
      ) : (
        <Table.ScrollContainer minWidth={760}>
          <Table striped highlightOnHover aria-label="Applications">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Application</Table.Th>
                <Table.Th>Kind</Table.Th>
                <Table.Th>Access</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Client ID / hosts</Table.Th>
                <Table.Th>Managed by</Table.Th>
                <Table.Th>
                  <VisuallyHidden>Actions</VisuallyHidden>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {q.data.map((a) => (
                <AppRow
                  key={a.id}
                  a={a}
                  onOpen={() => {
                    select(a.id)
                  }}
                />
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      <AppCreateModal
        tenant={tenant}
        opened={creating}
        onClose={closeCreate}
        onCreated={(a) => {
          closeCreate()
          if (a.client_secret && a.client) {
            setSecret({ title: `${a.name} created`, clientId: a.client.client_id, secret: a.client_secret })
          }
          select(a.id)
        }}
      />
      <Drawer
        opened={!!app && !secret}
        onClose={() => {
          select(undefined)
        }}
        position="right"
        size="xl"
        title={current?.name ?? 'Application'}
      >
        {app ? (
          <AppDetail
            tenant={tenant}
            appId={app}
            onDeleted={() => {
              select(undefined)
            }}
          />
        ) : null}
      </Drawer>
      <SecretModal
        value={secret}
        onClose={() => {
          setSecret(null)
        }}
      />
    </Stack>
  )
}

function AppRow({ a, onOpen }: { a: Application; onOpen: () => void }) {
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" fw={500}>
          {a.name}
        </Text>
        <Text size="xs" c="dimmed">
          {a.slug}
        </Text>
      </Table.Td>
      <Table.Td>
        <Tag variant="light" color={a.kind === 'oidc' ? 'blue' : 'grape'}>
          {a.kind === 'oidc' ? 'OIDC' : 'Forward-auth'}
        </Tag>
      </Table.Td>
      <Table.Td>
        <Text size="sm">{a.access_mode === 'assigned' ? 'Assigned only' : 'All members'}</Text>
      </Table.Td>
      <Table.Td>
        <Tag variant="light" color={a.enabled ? 'green' : 'gray'}>
          {a.enabled ? 'enabled' : 'disabled'}
        </Tag>
      </Table.Td>
      <Table.Td>
        <Text size="xs" ff="monospace" style={{ overflowWrap: 'anywhere' }}>
          {a.client ? a.client.client_id : a.hosts.join(', ')}
        </Text>
      </Table.Td>
      <Table.Td>
        <ProvenanceTag managedBy={a.managed_by} lastChangedBy={a.last_changed_by} />
      </Table.Td>
      <Table.Td>
        <Group justify="flex-end">
          <Button size="xs" variant="default" onClick={onOpen} aria-label={`Manage ${a.name}`}>
            Manage
          </Button>
        </Group>
      </Table.Td>
    </Table.Tr>
  )
}
