import { Button, Card, Group, Select, Stack, Table, Text, TextInput, Tooltip, VisuallyHidden } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { adminQuery, useAdminMutation } from '@/api/admin'
import {
  addMember,
  membersQuery,
  removeMember,
  setMemberStatus,
  tenantKeys,
  usersQuery,
  when,
  type Member,
} from '@/api/admin/tenant'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { LoadingRows, MutationError, Section, ProvenanceTag, Tag } from '@/components/admin/tenant/common'

export const Route = createFileRoute('/_app/admin/t/$tenant/members')({
  component: MembersPage,
})

function MembersPage() {
  const { tenant } = Route.useParams()
  const caps = useQuery(adminQuery)
  const operator = caps.data?.installation ?? false
  return (
    <Stack gap="xl">
      <PageHeader
        title="Members"
        description="People who belong to this tenant. Members can sign in to the tenant's applications; suspended members keep their history but cannot sign in here. Domain rules and invitations add members automatically."
      />
      <AddMember tenant={tenant} operator={operator} />
      <MemberList tenant={tenant} />
    </Stack>
  )
}

/** Describes where a membership came from. */
function SourceBadge({ source }: { source: string }) {
  const [kind, ref] = source.split(':', 2)
  const labels: Record<string, string> = {
    manual: 'Added manually',
    terraform: 'Terraform',
    setup: 'Setup',
    domain_rule: 'Domain rule',
    dirsync: 'Directory sync',
    invite: 'Invitation',
  }
  const badge = (
    <Tag variant="outline" color="gray" size="sm">
      {labels[kind] ?? kind}
    </Tag>
  )
  return ref ? <Tooltip label={`${labels[kind] ?? kind} ${ref}`}>{badge}</Tooltip> : badge
}

function MemberList({ tenant }: { tenant: string }) {
  const q = useInfiniteQuery(membersQuery(tenant))
  const members = q.data?.pages.flatMap((p) => p.items) ?? []
  return (
    <Section title="Current members">
      {q.error ? <ErrorAlert error={q.error} /> : null}
      {q.isPending ? (
        <LoadingRows />
      ) : members.length === 0 && !q.error ? (
        <EmptyState>No members yet. Add a user above or create a domain rule or invitation.</EmptyState>
      ) : (
        <Table.ScrollContainer minWidth={760}>
          <Table striped highlightOnHover aria-label="Tenant members">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Person</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Source</Table.Th>
                <Table.Th>Managed by</Table.Th>
                <Table.Th>Member since</Table.Th>
                <Table.Th>
                  <VisuallyHidden>Actions</VisuallyHidden>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {members.map((m) => (
                <MemberRow key={m.id} tenant={tenant} m={m} />
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {q.hasNextPage ? (
        <Group justify="center">
          <Button variant="default" onClick={() => void q.fetchNextPage()} loading={q.isFetchingNextPage}>
            Load more
          </Button>
        </Group>
      ) : null}
    </Section>
  )
}

function MemberRow({ tenant, m }: { tenant: string; m: Member }) {
  const name = m.display_name ?? m.email ?? m.user_id
  const status = useAdminMutation({
    mutationFn: (s: Member['status']) => setMemberStatus(tenant, m, s),
    success: (r) => `${name} is now ${r.status}`,
    invalidate: [tenantKeys.members(tenant)],
  })
  const remove = useAdminMutation({
    mutationFn: () => removeMember(tenant, m),
    success: `${name} was removed from the tenant`,
    invalidate: [tenantKeys.members(tenant)],
  })
  const next = m.status === 'active' ? 'suspended' : 'active'
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" fw={500}>
          {name}
        </Text>
        {m.email && m.email !== name ? (
          <Text size="xs" c="dimmed">
            {m.email}
          </Text>
        ) : null}
        <Text size="xs" c="dimmed" ff="monospace">
          {m.user_id}
        </Text>
      </Table.Td>
      <Table.Td>
        <Tag color={m.status === 'active' ? 'green' : 'orange'} variant="light">
          {m.status}
        </Tag>
      </Table.Td>
      <Table.Td>
        <SourceBadge source={m.source} />
      </Table.Td>
      <Table.Td>
        <ProvenanceTag managedBy={m.managed_by} lastChangedBy={m.last_changed_by} />
      </Table.Td>
      <Table.Td>
        <Text size="sm">{when(m.created_at)}</Text>
      </Table.Td>
      <Table.Td>
        <Group gap="xs" justify="flex-end" wrap="nowrap">
          <Button
            size="xs"
            variant="default"
            loading={status.isPending}
            onClick={() => {
              status.mutate(next)
            }}
            aria-label={`${next === 'suspended' ? 'Suspend' : 'Reactivate'} ${name}`}
          >
            {next === 'suspended' ? 'Suspend' : 'Reactivate'}
          </Button>
          <ConfirmButton
            variant="default"
            label="Remove"
            title={`Remove ${name}?`}
            loading={remove.isPending}
            onConfirm={() => remove.mutateAsync().catch(() => undefined)}
          >
            <Text size="sm">
              {name} loses access to this tenant's applications and their role assignments here stop applying. Members
              added by a domain rule are added again at their next sign-in unless the rule is removed.
            </Text>
          </ConfirmButton>
        </Group>
      </Table.Td>
    </Table.Tr>
  )
}

function AddMember({ tenant, operator }: { tenant: string; operator: boolean }) {
  const form = useForm({
    initialValues: { userId: '' },
    validate: { userId: (v) => (v.trim() ? null : 'Choose a user') },
  })
  const add = useAdminMutation({
    mutationFn: (userId: string) => addMember(tenant, userId),
    success: (m) => `${m.display_name ?? m.email ?? m.user_id} added`,
    invalidate: [tenantKeys.members(tenant)],
    onSuccess: () => {
      form.reset()
    },
  })
  return (
    <Card>
      <form
        onSubmit={form.onSubmit((v) => {
          add.mutate(v.userId.trim())
        })}
      >
        <Stack>
          <Text component="h2" fw={600} size="lg" m={0}>
            Add a member
          </Text>
          <Text size="sm" c="dimmed">
            Adds an existing Porch user. To bring in someone who has never signed in, send an invitation instead.
          </Text>
          <Group align="flex-end" wrap="wrap">
            {operator ? (
              <UserPicker {...form.getInputProps('userId')} />
            ) : (
              <TextInput
                label="User ID"
                description="Ask an installation administrator for the user's ID"
                required
                maw={420}
                style={{ flex: 1 }}
                {...form.getInputProps('userId')}
              />
            )}
            <Button type="submit" loading={add.isPending}>
              Add member
            </Button>
          </Group>
          <MutationError error={add.error} />
        </Stack>
      </form>
    </Card>
  )
}

/** Searchable list of installation users (operators only: GET /users needs an installation role). */
function UserPicker(props: { value?: string; onChange: (v: string) => void; error?: unknown }) {
  const users = useQuery(usersQuery(''))
  return (
    <Select
      label="User"
      description="Installation users (first 200 active)"
      placeholder={users.isPending ? 'Loading users…' : 'Search by name or email'}
      searchable
      required
      nothingFoundMessage="No matching user"
      maw={420}
      style={{ flex: 1 }}
      data={(users.data?.items ?? []).map((u) => ({
        value: u.id,
        label: u.primary_email ? `${u.display_name} <${u.primary_email}>` : u.display_name,
      }))}
      value={props.value ?? null}
      onChange={(v) => {
        props.onChange(v ?? '')
      }}
      error={typeof props.error === 'string' ? props.error : users.error ? 'Could not load users' : undefined}
    />
  )
}
