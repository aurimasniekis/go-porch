import { Button, Card, Group, Select, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { useAdminMutation } from '@/api/admin'
import { createInvite, deleteInvite, invitesQuery, tenantKeys, when, type Invite } from '@/api/admin/tenant'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { LoadingRows, MutationError, Section, Tag } from '@/components/admin/tenant/common'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/t/$tenant/invites')({
  component: InvitesPage,
})

const validity = [
  { value: String(86400), label: '1 day' },
  { value: String(3 * 86400), label: '3 days' },
  { value: String(7 * 86400), label: '7 days' },
  { value: String(14 * 86400), label: '14 days' },
  { value: String(30 * 86400), label: '30 days' },
]

function InvitesPage() {
  const { tenant } = Route.useParams()
  return (
    <Stack gap="xl">
      <PageHeader
        title="Invitations"
        description="Allow a specific email address to join this tenant. The invitation is accepted the first time that person signs in with an identity provider account whose verified email matches exactly. Porch does not send email: tell them to sign in."
      />
      <CreateInvite tenant={tenant} />
      <InviteList tenant={tenant} />
    </Stack>
  )
}

type InviteState = 'pending' | 'accepted' | 'expired'

function stateOf(i: Invite, now: number): InviteState {
  if (i.consumed_at) return 'accepted'
  return new Date(i.expires_at).getTime() <= now ? 'expired' : 'pending'
}

const stateColor: Record<InviteState, string> = { pending: 'blue', accepted: 'green', expired: 'gray' }

function InviteList({ tenant }: { tenant: string }) {
  const q = useQuery(invitesQuery(tenant))
  const [now] = useState(() => Date.now())
  return (
    <Section title="Sent invitations">
      {q.error ? <ErrorAlert error={q.error} /> : null}
      {q.isPending ? (
        <LoadingRows />
      ) : !q.data?.length ? (
        q.error ? null : (
          <EmptyState>No invitations yet.</EmptyState>
        )
      ) : (
        <ListTable minWidth={640} striped aria-label="Invitations">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Email</Table.Th>
              <Table.Th>State</Table.Th>
              <Table.Th>Sent</Table.Th>
              <Table.Th>Expires / accepted</Table.Th>
              <Table.Th>
                <VisuallyHidden>Actions</VisuallyHidden>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data.map((i) => (
              <InviteRow key={i.id} tenant={tenant} invite={i} state={stateOf(i, now)} />
            ))}
          </Table.Tbody>
        </ListTable>
      )}
    </Section>
  )
}

function InviteRow({ tenant, invite, state }: { tenant: string; invite: Invite; state: InviteState }) {
  const del = useAdminMutation({
    mutationFn: () => deleteInvite(tenant, invite.id),
    success: state === 'pending' ? `Invitation for ${invite.email} revoked` : 'Invitation deleted',
    invalidate: [tenantKeys.invites(tenant)],
  })
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm">{invite.email}</Text>
      </Table.Td>
      <Table.Td>
        <Tag variant="light" color={stateColor[state]}>
          {state}
        </Tag>
      </Table.Td>
      <Table.Td>
        <Text size="sm">{when(invite.created_at)}</Text>
      </Table.Td>
      <Table.Td>
        <Text size="sm">{state === 'accepted' ? when(invite.consumed_at) : when(invite.expires_at)}</Text>
      </Table.Td>
      <Table.Td>
        <Group justify="flex-end">
          <ConfirmButton
            variant="default"
            label={state === 'pending' ? 'Revoke' : 'Delete'}
            title={state === 'pending' ? `Revoke the invitation for ${invite.email}?` : 'Delete this invitation?'}
            loading={del.isPending}
            onConfirm={() => del.mutateAsync().catch(() => undefined)}
          >
            <Text size="sm">
              {state === 'pending'
                ? 'The invitation stops working immediately. People who already joined stay members.'
                : 'Removes the record. Membership created by an accepted invitation is not affected.'}
            </Text>
          </ConfirmButton>
        </Group>
      </Table.Td>
    </Table.Tr>
  )
}

function CreateInvite({ tenant }: { tenant: string }) {
  const form = useForm({
    initialValues: { email: '', valid: String(7 * 86400) },
    validate: { email: (v) => (/^[^\s@]+@[^\s@]+$/.test(v.trim()) ? null : 'Enter an email address') },
  })
  const create = useAdminMutation({
    mutationFn: (v: { email: string; valid: string }) => createInvite(tenant, v.email.trim(), Number(v.valid)),
    success: (i) => `Invitation created for ${i.email}`,
    invalidate: [tenantKeys.invites(tenant)],
    onSuccess: () => {
      form.reset()
    },
  })
  return (
    <Card>
      <form
        onSubmit={form.onSubmit((v) => {
          create.mutate(v)
        })}
      >
        <Stack>
          <Text component="h2" fw={600} size="lg" m={0}>
            Invite by email
          </Text>
          <Group align="flex-end" wrap="wrap">
            <TextInput
              label="Email address"
              type="email"
              required
              autoComplete="off"
              maw={360}
              style={{ flex: 1, minWidth: 220 }}
              {...form.getInputProps('email')}
            />
            <Select label="Valid for" data={validity} allowDeselect={false} w={160} {...form.getInputProps('valid')} />
            <Button type="submit" loading={create.isPending}>
              Create invitation
            </Button>
          </Group>
          <MutationError error={create.error} />
        </Stack>
      </form>
    </Card>
  )
}
