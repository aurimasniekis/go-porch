import { Anchor, Button, Card, Group, Stack, Table, Text, VisuallyHidden } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { useState } from 'react'
import { useAdminMutation } from '@/api/admin'
import {
  deleteServiceAccount,
  rotateServiceAccountSecret,
  seconds,
  serviceAccountsQuery,
  tenantKeys,
  when,
  type CreatedServiceAccount,
  type ServiceAccount,
} from '@/api/admin/tenant'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { LoadingRows, ProvenanceTag, Tag } from '@/components/admin/tenant/common'
import { SecretModal, type OneTimeSecret } from '@/components/admin/tenant/SecretModal'
import {
  CreateServiceAccountModal,
  CurlExample,
  EditServiceAccountModal,
} from '@/components/admin/tenant/ServiceAccountForms'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/t/$tenant/service-accounts')({
  component: ServiceAccountsPage,
})

interface Revealed extends OneTimeSecret {
  sa: Pick<ServiceAccount, 'token_endpoint' | 'id' | 'audiences'>
}

function ServiceAccountsPage() {
  const { tenant } = Route.useParams()
  const q = useQuery(serviceAccountsQuery(tenant))
  const [creating, { open, close }] = useDisclosure(false)
  const [editing, setEditing] = useState<string | null>(null)
  const [secret, setSecret] = useState<Revealed | null>(null)
  const editingSA = q.data?.find((s) => s.id === editing)
  const reveal = (sa: Revealed['sa'] & { name: string }, value: string, title: string) => {
    setSecret({ title, clientId: sa.id, secret: value, sa })
  }
  return (
    <Stack gap="lg">
      <PageHeader
        title="Service accounts"
        description={
          <>
            Machine identities that obtain access tokens with the OAuth client credentials grant (client ID and secret,
            no user involved). A new service account can do nothing: grant it roles on the{' '}
            <Anchor
              inherit
              underline="always"
              renderRoot={(props) => <Link to="/admin/t/$tenant/assignments" params={{ tenant }} {...props} />}
            >
              Assignments
            </Anchor>{' '}
            page with subject type <em>service_account</em>.
          </>
        }
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={open}>
            New service account
          </Button>
        }
      />
      {q.error ? <ErrorAlert error={q.error} /> : null}
      {q.isPending ? (
        <LoadingRows />
      ) : !q.data?.length ? (
        q.error ? null : (
          <EmptyState>No service accounts yet.</EmptyState>
        )
      ) : (
        <>
          <ListTable minWidth={820} striped highlightOnHover aria-label="Service accounts">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Service account</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Audiences</Table.Th>
                <Table.Th>Token lifetime</Table.Th>
                <Table.Th>Secret</Table.Th>
                <Table.Th>Last used</Table.Th>
                <Table.Th>Managed by</Table.Th>
                <Table.Th>
                  <VisuallyHidden>Actions</VisuallyHidden>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {q.data.map((sa) => (
                <SARow
                  key={sa.id}
                  tenant={tenant}
                  sa={sa}
                  onEdit={() => {
                    setEditing(sa.id)
                  }}
                  onRotated={(s) => {
                    reveal(sa, s, `New secret for ${sa.name}`)
                  }}
                />
              ))}
            </Table.Tbody>
          </ListTable>
          <Card>
            <CurlExample sa={q.data[0]} />
          </Card>
        </>
      )}
      <CreateServiceAccountModal
        tenant={tenant}
        opened={creating}
        onClose={close}
        onCreated={(sa: CreatedServiceAccount) => {
          close()
          reveal(sa, sa.client_secret, `${sa.name} created`)
        }}
      />
      {editingSA ? (
        <EditServiceAccountModal
          key={editingSA.id}
          tenant={tenant}
          sa={editingSA}
          onClose={() => {
            setEditing(null)
          }}
        />
      ) : null}
      <SecretModal
        value={secret}
        onClose={() => {
          setSecret(null)
        }}
      >
        {secret ? <CurlExample sa={secret.sa} /> : null}
      </SecretModal>
    </Stack>
  )
}

function SARow({
  tenant,
  sa,
  onEdit,
  onRotated,
}: {
  tenant: string
  sa: ServiceAccount
  onEdit: () => void
  onRotated: (secret: string) => void
}) {
  const rotate = useAdminMutation({
    mutationFn: () => rotateServiceAccountSecret(tenant, sa.id),
    success: 'New secret issued; the old one no longer works',
    invalidate: [tenantKeys.serviceAccounts(tenant)],
    onSuccess: (s) => {
      onRotated(s.client_secret)
    },
  })
  const del = useAdminMutation({
    mutationFn: () => deleteServiceAccount(tenant, sa),
    success: `Service account ${sa.name} deleted`,
    invalidate: [tenantKeys.serviceAccounts(tenant)],
  })
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" fw={500}>
          {sa.name}
        </Text>
        <Text size="xs" c="dimmed">
          {sa.slug}
        </Text>
        <Text size="xs" c="dimmed" ff="monospace">
          {sa.id}
        </Text>
      </Table.Td>
      <Table.Td>
        <Tag variant="light" color={sa.enabled ? 'green' : 'gray'}>
          {sa.enabled ? 'enabled' : 'disabled'}
        </Tag>
      </Table.Td>
      <Table.Td>
        {sa.audiences.length ? (
          sa.audiences.map((a) => (
            <Text key={a} size="xs" ff="monospace" style={{ overflowWrap: 'anywhere' }}>
              {a}
            </Text>
          ))
        ) : (
          <Text size="xs" c="dimmed">
            none (cannot get tokens)
          </Text>
        )}
      </Table.Td>
      <Table.Td>
        <Text size="sm">{seconds(sa.access_token_ttl_seconds)}</Text>
      </Table.Td>
      <Table.Td>
        <Text size="xs" c="dimmed">
          {sa.secret_hint ? `…${sa.secret_hint}` : '—'}
        </Text>
      </Table.Td>
      <Table.Td>
        <Text size="sm">{when(sa.last_used_at)}</Text>
      </Table.Td>
      <Table.Td>
        <ProvenanceTag managedBy={sa.managed_by} lastChangedBy={sa.last_changed_by} />
      </Table.Td>
      <Table.Td>
        <Group gap="xs" justify="flex-end" wrap="nowrap">
          <Button size="xs" variant="default" onClick={onEdit} aria-label={`Edit ${sa.name}`}>
            Edit
          </Button>
          <ConfirmButton
            variant="default"
            label="Rotate secret"
            title={`Issue a new secret for ${sa.name}?`}
            color="orange"
            loading={rotate.isPending}
            onConfirm={() => rotate.mutateAsync().catch(() => undefined)}
          >
            <Text size="sm">The current secret stops working immediately. This needs a recent sign-in.</Text>
          </ConfirmButton>
          <ConfirmButton
            variant="default"
            label="Delete"
            title={`Delete ${sa.name}?`}
            loading={del.isPending}
            onConfirm={() => del.mutateAsync().catch(() => undefined)}
          >
            <Text size="sm">
              The service account and its role assignments are removed; tokens can no longer be issued for it.
            </Text>
          </ConfirmButton>
        </Group>
      </Table.Td>
    </Table.Tr>
  )
}
