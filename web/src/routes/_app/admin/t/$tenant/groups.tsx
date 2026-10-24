import {
  Alert,
  Button,
  Divider,
  Group,
  Select,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Title,
  Modal,
} from '@mantine/core'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, ifMatch, useAdminMutation } from '@/api/admin'
import {
  authzInvalidate,
  conflictAware,
  groupsQuery,
  memberLabel,
  mayListMembers,
  membersQuery,
  type Group as GroupT,
} from '@/api/admin/authz'
import { api, check, unwrap } from '@/api/client'
import { LoadingState, ManagedBy, MutationError } from '@/components/admin/authz/common'
import { groupDescendants, slugify, validSlug } from '@/components/admin/authz/logic'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'

export const Route = createFileRoute('/_app/admin/t/$tenant/groups')({
  component: GroupsPage,
})

type OpenDialog = { kind: 'create' } | { kind: 'edit'; id: string } | { kind: 'manage'; id: string } | null

function GroupsPage() {
  const { tenant } = Route.useParams()
  const groups = useQuery(groupsQuery(tenant))
  const [dialog, setDialog] = useState<OpenDialog>(null)
  const del = useAdminMutation({
    mutationFn: async (g: GroupT) => {
      check(await api.DELETE('/tenants/{tenant}/groups/{group}', { params: { path: { tenant, group: g.id } } }))
    },
    success: 'Group deleted',
    invalidate: authzInvalidate(tenant),
  })
  const list = groups.data ?? []
  const byId = new Map(list.map((g) => [g.id, g]))
  const current = dialog && dialog.kind !== 'create' ? byId.get(dialog.id) : undefined
  return (
    <>
      <PageHeader
        title="Groups"
        description="Groups collect members. Roles assigned to a group reach its members and the members of groups nested inside it."
        actions={
          <Button
            leftSection={<IconPlus size={16} aria-hidden />}
            onClick={() => {
              setDialog({ kind: 'create' })
            }}
          >
            New group
          </Button>
        }
      />
      <ErrorAlert error={groups.error} title="Could not load groups" />
      {groups.isPending ? <LoadingState label="Loading groups…" /> : null}
      {groups.data?.length === 0 ? <EmptyState>No groups yet. Create one to organise members.</EmptyState> : null}
      {list.length > 0 ? (
        <Table.ScrollContainer minWidth={720}>
          <Table striped highlightOnHover aria-label="Groups" verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Group</Table.Th>
                <Table.Th>Direct members</Table.Th>
                <Table.Th>Member of</Table.Th>
                <Table.Th>Managed by</Table.Th>
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {list.map((g) => (
                <Table.Tr key={g.id}>
                  <Table.Td>
                    <Text fw={500}>{g.name}</Text>
                    <Text size="xs" c="dimmed">
                      {g.slug}
                    </Text>
                  </Table.Td>
                  <Table.Td>{g.members.length}</Table.Td>
                  <Table.Td>
                    <Text size="sm">
                      {g.parents.length > 0 ? g.parents.map((p) => byId.get(p)?.name ?? p).join(', ') : '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <ManagedBy managedBy={g.managed_by} />
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end" wrap="nowrap">
                      <Button
                        size="xs"
                        variant="light"
                        aria-label={`Members & nesting of ${g.name}`}
                        onClick={() => {
                          setDialog({ kind: 'manage', id: g.id })
                        }}
                      >
                        Members & nesting
                      </Button>
                      <Button
                        size="xs"
                        variant="default"
                        aria-label={`Rename ${g.name}`}
                        onClick={() => {
                          setDialog({ kind: 'edit', id: g.id })
                        }}
                      >
                        Rename
                      </Button>
                      <ConfirmButton
                        variant="default"
                        label="Delete"
                        title={`Delete group ${g.name}?`}
                        confirmLabel="Delete group"
                        loading={del.isPending}
                        onConfirm={() => del.mutateAsync(g).catch(() => undefined)}
                      >
                        <Text size="sm">
                          Its memberships, nesting and role assignments are removed; members lose what the group granted
                          them. This cannot be undone.
                        </Text>
                      </ConfirmButton>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : null}
      {dialog?.kind === 'create' ? (
        <GroupForm
          tenant={tenant}
          onClose={() => {
            setDialog(null)
          }}
        />
      ) : null}
      {dialog?.kind === 'edit' && current ? (
        <GroupForm
          tenant={tenant}
          group={current}
          onClose={() => {
            setDialog(null)
          }}
        />
      ) : null}
      {dialog?.kind === 'manage' && current ? (
        <ManageGroup
          tenant={tenant}
          group={current}
          groups={list}
          onClose={() => {
            setDialog(null)
          }}
        />
      ) : null}
    </>
  )
}

function GroupForm({ tenant, group, onClose }: { tenant: string; group?: GroupT; onClose: () => void }) {
  const [name, setName] = useState(group?.name ?? '')
  const [slug, setSlug] = useState(group?.slug ?? '')
  const [slugTouched, setSlugTouched] = useState(false)
  const [description, setDescription] = useState(group?.description ?? '')
  const [submitted, setSubmitted] = useState(false)
  const save = useAdminMutation({
    mutationFn: async () => {
      if (group) {
        return conflictAware(
          (async () =>
            unwrap(
              await api.PATCH('/tenants/{tenant}/groups/{group}', {
                params: { path: { tenant, group: group.id }, header: ifMatch(group.version) },
                body: { name: name.trim(), description },
              }),
            ))(),
        )
      }
      return unwrap(
        await api.POST('/tenants/{tenant}/groups', {
          params: { path: { tenant } },
          body: { name: name.trim(), slug, description },
        }),
      )
    },
    success: (g) => (group ? `Group ${g.name} saved` : `Group ${g.name} created`),
    invalidate: authzInvalidate(tenant),
    onSuccess: onClose,
  })
  return (
    <Modal centered opened onClose={onClose} title={group ? `Rename group ${group.name}` : 'New group'}>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          setSubmitted(true)
          if (!name.trim() || (!group && !validSlug(slug))) return
          save.mutate()
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            required
            data-autofocus
            value={name}
            maxLength={200}
            error={submitted && !name.trim() ? 'Required' : null}
            onChange={(e) => {
              const v = e.currentTarget.value
              setName(v)
              if (!group && !slugTouched) setSlug(slugify(v))
            }}
          />
          {group ? null : (
            <TextInput
              label="Slug"
              description="Shown to policies (inGroup) and in tokens; cannot be changed later."
              required
              value={slug}
              maxLength={63}
              error={submitted && !validSlug(slug) ? 'Lowercase letters, digits and inner hyphens' : null}
              onChange={(e) => {
                setSlugTouched(true)
                setSlug(e.currentTarget.value)
              }}
            />
          )}
          <Textarea
            label="Description"
            value={description}
            maxLength={2000}
            autosize
            minRows={2}
            onChange={(e) => {
              setDescription(e.currentTarget.value)
            }}
          />
          <MutationError error={save.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              {group ? 'Save group' : 'Create group'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

function ManageGroup({
  tenant,
  group,
  groups,
  onClose,
}: {
  tenant: string
  group: GroupT
  groups: GroupT[]
  onClose: () => void
}) {
  const caps = useQuery(adminQuery)
  const mayList = mayListMembers(caps.data?.tenants.find((t) => t.slug === tenant || t.id === tenant))
  const members = useQuery({ ...membersQuery(tenant), enabled: mayList })
  const [pickMember, setPickMember] = useState<string | null>(null)
  const [pickParent, setPickParent] = useState<string | null>(null)
  const byUser = new Map((members.data ?? []).map((m) => [m.user_id, m]))
  const byGroup = new Map(groups.map((g) => [g.id, g]))
  const invalidate = authzInvalidate(tenant)

  const addMember = useAdminMutation({
    mutationFn: async (user: string) => {
      check(
        await api.PUT('/tenants/{tenant}/groups/{group}/members/{user}', {
          params: { path: { tenant, group: group.id, user } },
        }),
      )
    },
    success: 'Member added',
    invalidate,
    onSuccess: () => {
      setPickMember(null)
    },
  })
  const removeMember = useAdminMutation({
    mutationFn: async (user: string) => {
      check(
        await api.DELETE('/tenants/{tenant}/groups/{group}/members/{user}', {
          params: { path: { tenant, group: group.id, user } },
        }),
      )
    },
    success: 'Member removed',
    invalidate,
  })
  const nest = useAdminMutation({
    mutationFn: async (parent: string) => {
      check(
        await api.PUT('/tenants/{tenant}/groups/{group}/parents/{parent}', {
          params: { path: { tenant, group: group.id, parent } },
        }),
      )
    },
    success: 'Group nested',
    invalidate,
    onSuccess: () => {
      setPickParent(null)
    },
  })
  const unnest = useAdminMutation({
    mutationFn: async (parent: string) => {
      check(
        await api.DELETE('/tenants/{tenant}/groups/{group}/parents/{parent}', {
          params: { path: { tenant, group: group.id, parent } },
        }),
      )
    },
    success: 'Removed from parent group',
    invalidate,
  })

  const memberOptions = (members.data ?? [])
    .filter((m) => !group.members.includes(m.user_id))
    .map((m) => ({ value: m.user_id, label: memberLabel(m) }))
  // Groups already below this one would create a cycle; the server enforces that and the depth limit.
  const below = groupDescendants(groups, group.id)
  const parentOptions = groups
    .filter((g) => g.id !== group.id && !group.parents.includes(g.id) && !below.has(g.id))
    .map((g) => ({ value: g.id, label: `${g.name} (${g.slug})` }))
  const children = groups.filter((g) => g.parents.includes(group.id))

  return (
    <Modal centered opened onClose={onClose} title={`Group ${group.name}`} size="xl">
      <Stack>
        <Title order={2} size="h4">
          Direct members
        </Title>
        <ErrorAlert error={members.error} title="Could not load tenant members" />
        {!mayList ? (
          <Alert color="gray">You cannot list the members of this tenant; members are shown by user ID.</Alert>
        ) : null}
        {group.members.length === 0 ? (
          <Text size="sm" c="dimmed">
            No direct members.
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={420}>
            <Table aria-label={`Direct members of ${group.name}`}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Member</Table.Th>
                  <Table.Th>
                    <span className="visually-hidden">Actions</span>
                  </Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {group.members.map((u) => {
                  const m = byUser.get(u)
                  const label = m ? memberLabel(m) : u
                  return (
                    <Table.Tr key={u}>
                      <Table.Td>{label}</Table.Td>
                      <Table.Td>
                        <Group justify="flex-end">
                          <Button
                            size="xs"
                            variant="default"
                            aria-label={`Remove ${label} from ${group.name}`}
                            loading={removeMember.isPending && removeMember.variables === u}
                            onClick={() => {
                              removeMember.mutate(u)
                            }}
                          >
                            Remove
                          </Button>
                        </Group>
                      </Table.Td>
                    </Table.Tr>
                  )
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (pickMember) addMember.mutate(pickMember)
          }}
        >
          <Group align="flex-end">
            <Select
              label="Add a member"
              placeholder={members.isPending && mayList ? 'Loading members…' : 'Search members'}
              data={memberOptions}
              value={pickMember}
              onChange={setPickMember}
              searchable
              clearable
              clearButtonProps={{ 'aria-label': 'Clear member selection' }}
              disabled={!mayList}
              nothingFoundMessage="No other members"
              style={{ flex: 1, minWidth: 220 }}
            />
            <Button type="submit" disabled={!pickMember} loading={addMember.isPending}>
              Add member
            </Button>
          </Group>
        </form>
        <MutationError error={addMember.error ?? removeMember.error} />

        <Divider />
        <Title order={2} size="h4">
          Member of (parent groups)
        </Title>
        <Text size="sm" c="dimmed">
          Members of {group.name} are also members of its parent groups. Nesting must not form a cycle and is limited to
          5 levels.
        </Text>
        {group.parents.length === 0 ? (
          <Text size="sm" c="dimmed">
            Not nested in any group.
          </Text>
        ) : (
          <Table aria-label={`Parent groups of ${group.name}`}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Parent group</Table.Th>
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {group.parents.map((p) => {
                const name = byGroup.get(p)?.name ?? p
                return (
                  <Table.Tr key={p}>
                    <Table.Td>{name}</Table.Td>
                    <Table.Td>
                      <Group justify="flex-end">
                        <Button
                          size="xs"
                          variant="default"
                          aria-label={`Unnest ${group.name} from ${name}`}
                          loading={unnest.isPending && unnest.variables === p}
                          onClick={() => {
                            unnest.mutate(p)
                          }}
                        >
                          Unnest
                        </Button>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                )
              })}
            </Table.Tbody>
          </Table>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (pickParent) nest.mutate(pickParent)
          }}
        >
          <Group align="flex-end">
            <Select
              label="Nest into group"
              placeholder="Choose a parent group"
              data={parentOptions}
              value={pickParent}
              onChange={setPickParent}
              searchable
              clearable
              clearButtonProps={{ 'aria-label': 'Clear parent group selection' }}
              nothingFoundMessage="No eligible groups"
              style={{ flex: 1, minWidth: 220 }}
            />
            <Button type="submit" disabled={!pickParent} loading={nest.isPending}>
              Nest
            </Button>
          </Group>
        </form>
        <MutationError error={nest.error ?? unnest.error} />
        {children.length > 0 ? (
          <Text size="sm">
            Groups nested inside {group.name}: {children.map((c) => c.name).join(', ')}
          </Text>
        ) : null}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Close
          </Button>
        </Group>
      </Stack>
    </Modal>
  )
}
