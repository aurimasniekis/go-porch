import { Button, Card, Group, Modal, Select, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus } from '@tabler/icons-react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import { useState, type SyntheticEvent } from 'react'
import { ifMatch, useAdminMutation } from '@/api/admin'
import { installKeys, userPagesQuery, type User, type UserFilter } from '@/api/admin/install'
import { api, ApiError, check, unwrap } from '@/api/client'
import { meQuery } from '@/api/queries'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { useVersionedMutation } from '@/components/admin/install/hooks'
import { ManagedBy } from '@/components/admin/install/ManagedBy'
import { StatusBadge, toneOf } from '@/components/admin/install/StatusBadge'
import { ConfirmAction } from '@/components/admin/install/ConfirmAction'
import { DateTime, Loading, Notice } from '@/components/admin/install/ui'

export const Route = createFileRoute('/_app/admin/i/users')({
  component: Users,
})

const statusOptions = [
  { value: '', label: 'Any status' },
  { value: 'active', label: 'Active' },
  { value: 'disabled', label: 'Disabled' },
]

function applyFieldErrors(e: unknown, setFieldError: (f: string, msg: string) => void) {
  if (e instanceof ApiError) for (const f of e.fields) setFieldError(f.field.replace(/^body\./, ''), f.message)
}

function Users() {
  const [draft, setDraft] = useState<UserFilter>({ query: '', status: '' })
  const [filter, setFilter] = useState<UserFilter>({ query: '', status: '' })
  const q = useInfiniteQuery(userPagesQuery(filter))
  const me = useQuery(meQuery)
  const [createOpened, createDisclosure] = useDisclosure(false)
  const [editing, setEditing] = useState<User | null>(null)
  const users = q.data?.pages.flatMap((p) => p.items) ?? []
  const filtered = !!(filter.query || filter.status)
  const search = (e: SyntheticEvent) => {
    e.preventDefault()
    setFilter({ query: draft.query.trim(), status: draft.status })
  }
  return (
    <Stack>
      <PageHeader
        title="Users"
        description="Everyone with an account on this installation. Users join tenants as members; disabling a user ends all of their sessions immediately."
        actions={
          <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={createDisclosure.open}>
            New user
          </Button>
        }
      />
      <Card component="form" onSubmit={search} padding="md" aria-label="Find users">
        <Group align="flex-end" wrap="wrap">
          <TextInput
            label="Search"
            description="Part of a name or email address"
            type="search"
            value={draft.query}
            onChange={(e) => {
              const query = e.currentTarget.value
              setDraft((d) => ({ ...d, query }))
            }}
            style={{ flex: '1 1 260px' }}
          />
          <Select
            label="Status"
            description="Account status"
            data={statusOptions}
            value={draft.status}
            allowDeselect={false}
            onChange={(v) => {
              setDraft((d) => ({ ...d, status: (v ?? '') as UserFilter['status'] }))
            }}
            w={180}
          />
          <Button type="submit">Search</Button>
          {filtered ? (
            <Button
              variant="default"
              onClick={() => {
                setDraft({ query: '', status: '' })
                setFilter({ query: '', status: '' })
              }}
            >
              Clear
            </Button>
          ) : null}
        </Group>
      </Card>
      <ErrorAlert error={q.error} title="Could not load users" />
      {q.isPending ? <Loading label="Loading users…" /> : null}
      {q.isSuccess && users.length === 0 ? (
        <EmptyState>{filtered ? 'No users match this search.' : 'No users yet.'}</EmptyState>
      ) : null}
      {users.length > 0 ? (
        <Table.ScrollContainer minWidth={980}>
          <Table striped highlightOnHover aria-label="Users" verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Email</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Last sign-in</Table.Th>
                <Table.Th>Managed by</Table.Th>
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {users.map((u) => (
                <UserRow
                  key={u.id}
                  u={u}
                  isMe={me.data?.user_id === u.id}
                  onEdit={() => {
                    setEditing(u)
                  }}
                />
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : null}
      {q.hasNextPage ? (
        <Group justify="center">
          <Button variant="default" loading={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
            Load more
          </Button>
        </Group>
      ) : null}
      <CreateUser opened={createOpened} onClose={createDisclosure.close} />
      <EditUser
        user={editing}
        onClose={() => {
          setEditing(null)
        }}
      />
    </Stack>
  )
}

function UserRow({ u, isMe, onEdit }: { u: User; isMe: boolean; onEdit: () => void }) {
  const endSessions = useAdminMutation({
    mutationFn: async () => {
      check(await api.POST('/users/{user}/revoke-sessions', { params: { path: { user: u.id } } }))
    },
    success: `All sessions of ${u.display_name} ended`,
    invalidate: [installKeys.sessions, installKeys.health],
    onSuccess: () => {
      if (isMe) window.location.assign('/login')
    },
  })
  const del = useVersionedMutation({
    mutationFn: async () => {
      check(await api.DELETE('/users/{user}', { params: { path: { user: u.id }, header: ifMatch(u.version) } }))
    },
    success: `${u.display_name} deleted`,
    invalidate: [installKeys.users, installKeys.health],
  })
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" fw={500}>
          {u.display_name}
          {isMe ? ' (you)' : ''}
        </Text>
        <Text size="xs" c="dimmed">
          {u.id}
        </Text>
      </Table.Td>
      <Table.Td>{u.primary_email ?? '—'}</Table.Td>
      <Table.Td>
        <StatusBadge tone={toneOf(u.status)}>{u.status}</StatusBadge>
      </Table.Td>
      <Table.Td>
        <DateTime value={u.last_login_at} />
      </Table.Td>
      <Table.Td>
        <ManagedBy managedBy={u.managed_by} lastChangedBy={u.last_changed_by} />
      </Table.Td>
      <Table.Td>
        <Group gap={6} wrap="nowrap">
          <Button size="xs" variant="default" onClick={onEdit}>
            Edit<VisuallyHidden> {u.display_name}</VisuallyHidden>
          </Button>
          <Button
            size="xs"
            variant="default"
            renderRoot={(props) => <Link {...props} to="/admin/i/sessions" search={{ user: u.id }} />}
          >
            Sessions<VisuallyHidden> of {u.display_name}</VisuallyHidden>
          </Button>
          <ConfirmAction
            label={
              <>
                End all sessions<VisuallyHidden> of {u.display_name}</VisuallyHidden>
              </>
            }
            confirmLabel="End all sessions"
            title={`End all sessions of ${u.display_name}?`}
            loading={endSessions.isPending}
            onConfirm={() => endSessions.mutateAsync(undefined).catch(() => undefined)}
          >
            <Text size="sm">
              {u.display_name} is signed out of Porch in every browser immediately. This needs a recent sign-in.
            </Text>
            {isMe ? (
              <Notice tone="warning" mt="sm" title="This includes your own session">
                You will be signed out too.
              </Notice>
            ) : null}
          </ConfirmAction>
          <ConfirmAction
            label={
              <>
                Delete<VisuallyHidden> {u.display_name}</VisuallyHidden>
              </>
            }
            confirmLabel="Delete user"
            title={`Delete ${u.display_name}?`}
            loading={del.isPending}
            onConfirm={() => del.mutateAsync(undefined).catch(() => undefined)}
          >
            <Text size="sm">
              The account, its sign-in identities, memberships and sessions are removed. This cannot be undone. Audit
              events about this user are kept.
            </Text>
          </ConfirmAction>
        </Group>
      </Table.Td>
    </Table.Tr>
  )
}

function CreateUser({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const form = useForm({
    initialValues: { display_name: '', primary_email: '' },
    validate: { display_name: (v) => (v.trim() ? null : 'Enter a name') },
  })
  const close = () => {
    form.reset()
    onClose()
  }
  const create = useAdminMutation({
    mutationFn: async (v: { display_name: string; primary_email: string }) =>
      unwrap(
        await api.POST('/users', {
          body: { display_name: v.display_name.trim(), primary_email: v.primary_email.trim() || undefined },
        }),
      ),
    success: (u) => `User ${u.display_name} created`,
    invalidate: [installKeys.users, installKeys.health],
    onSuccess: close,
  })
  return (
    <Modal
      closeButtonProps={{ 'aria-label': 'Close' }}
      lockScroll={false}
      opened={opened}
      onClose={close}
      title="New user"
      centered
    >
      <form
        onSubmit={form.onSubmit((v) => {
          create.mutate(v, {
            onError: (e) => {
              applyFieldErrors(e, form.setFieldError)
            },
          })
        })}
      >
        <Stack>
          <TextInput label="Display name" required data-autofocus {...form.getInputProps('display_name')} />
          <TextInput
            label="Primary email"
            type="email"
            description="Contact attribute only: it is never used to link sign-in accounts."
            {...form.getInputProps('primary_email')}
          />
          <Text size="xs" c="dimmed">
            To let the user sign in, add them to a tenant (invitation or domain rule) or link a sign-in account.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Create user
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

interface EditValues {
  display_name: string
  primary_email: string
  status: 'active' | 'disabled'
}

function EditUser({ user, onClose }: { user: User | null; onClose: () => void }) {
  return (
    <Modal
      closeButtonProps={{ 'aria-label': 'Close' }}
      lockScroll={false}
      opened={!!user}
      onClose={onClose}
      title={user ? `Edit ${user.display_name}` : 'Edit user'}
      centered
    >
      {user ? <EditUserForm key={`${user.id}:${String(user.version)}`} user={user} onClose={onClose} /> : null}
    </Modal>
  )
}

function EditUserForm({ user, onClose }: { user: User; onClose: () => void }) {
  const form = useForm<EditValues>({
    initialValues: { display_name: user.display_name, primary_email: user.primary_email ?? '', status: user.status },
    validate: { display_name: (v) => (v.trim() ? null : 'Enter a name') },
  })
  const save = useVersionedMutation({
    mutationFn: async (v: EditValues) => {
      const body: { display_name?: string; primary_email?: string; status?: 'active' | 'disabled' } = {}
      if (v.display_name.trim() !== user.display_name) body.display_name = v.display_name.trim()
      if (v.primary_email.trim() !== (user.primary_email ?? '')) body.primary_email = v.primary_email.trim()
      if (v.status !== user.status) body.status = v.status
      return unwrap(
        await api.PATCH('/users/{user}', { params: { path: { user: user.id }, header: ifMatch(user.version) }, body }),
      )
    },
    success: (u) => `${u.display_name} saved`,
    invalidate: [installKeys.users, installKeys.sessions],
    onSuccess: onClose,
  })
  const unlock = useAdminMutation({
    mutationFn: async () => {
      check(await api.POST('/users/{user}/backup-lockout/unlock', { params: { path: { user: user.id } } }))
    },
    success: `Backup-login lockout of ${user.display_name} cleared`,
  })
  const disabling = form.values.status === 'disabled' && user.status === 'active'
  return (
    <form
      onSubmit={form.onSubmit((v) => {
        save.mutate(v, {
          onError: (e) => {
            applyFieldErrors(e, form.setFieldError)
          },
        })
      })}
    >
      <Stack>
        <TextInput label="Display name" required data-autofocus {...form.getInputProps('display_name')} />
        <TextInput
          label="Primary email"
          type="email"
          description="Contact attribute only: it is never used to link sign-in accounts."
          {...form.getInputProps('primary_email')}
        />
        <Select
          label="Status"
          data={[
            { value: 'active', label: 'Active' },
            { value: 'disabled', label: 'Disabled' },
          ]}
          allowDeselect={false}
          {...form.getInputProps('status')}
        />
        {disabling ? (
          <Notice tone="warning" title="Disabling signs the user out">
            All of {user.display_name}&apos;s sessions end immediately and they cannot sign in until enabled again.
          </Notice>
        ) : null}
        <Card padding="sm">
          <Text size="sm" fw={500}>
            Backup login
          </Text>
          <Text size="xs" c="dimmed" mb="xs">
            A wrong backup password or answer locks the user&apos;s backup login for several hours. Clear the lockout
            only after confirming the user&apos;s identity out of band. Needs a recent sign-in.
          </Text>
          <Button
            size="xs"
            variant="default"
            loading={unlock.isPending}
            onClick={() => {
              unlock.mutate(undefined)
            }}
          >
            Clear backup-login lockout
          </Button>
        </Card>
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending} disabled={!form.isDirty()}>
            Save changes
          </Button>
        </Group>
      </Stack>
    </form>
  )
}
