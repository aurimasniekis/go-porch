import { Alert, Button, Group, MultiSelect, Stack, Table, Text, Textarea, TextInput, Modal } from '@mantine/core'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { can, ifMatch, useAdminMutation, useAdminTenant } from '@/api/admin'
import { authzInvalidate, conflictAware, permissionsQuery, rolesQuery, type Role } from '@/api/admin/authz'
import { api, check, unwrap } from '@/api/client'
import { LoadingState, ManagedBy, MutationError, Perm, Tag } from '@/components/admin/authz/common'
import { PermissionPicker } from '@/components/admin/authz/inputs'
import { slugify, validSlug } from '@/components/admin/authz/logic'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader, ReadOnlyNote } from '@/components/admin/kit'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/t/$tenant/roles')({
  component: RolesPage,
})

type Editing = { mode: 'create' } | { mode: 'edit'; role: Role } | null

function RolesPage() {
  const { tenant } = Route.useParams()
  const roles = useQuery(rolesQuery(tenant))
  const manage = can(useAdminTenant(tenant), 'role:manage')
  const [editing, setEditing] = useState<Editing>(null)
  const del = useAdminMutation({
    mutationFn: async (r: Role) => {
      check(await api.DELETE('/tenants/{tenant}/roles/{role}', { params: { path: { tenant, role: r.id } } }))
    },
    success: 'Role deleted',
    invalidate: authzInvalidate(tenant),
  })
  const byId = new Map((roles.data ?? []).map((r) => [r.id, r]))
  return (
    <>
      <PageHeader
        title="Roles"
        description="A role bundles permissions (and optionally other roles). Assign roles to members, groups or service accounts on the Assignments page."
        actions={
          manage ? (
            <Button
              leftSection={<IconPlus size={16} aria-hidden />}
              onClick={() => {
                setEditing({ mode: 'create' })
              }}
            >
              New role
            </Button>
          ) : null
        }
      />
      {manage ? null : <ReadOnlyNote what="roles" />}
      <ErrorAlert error={roles.error} title="Could not load roles" />
      {roles.isPending ? <LoadingState label="Loading roles…" /> : null}
      {roles.data?.length === 0 ? <EmptyState>No roles yet.</EmptyState> : null}
      {roles.data && roles.data.length > 0 ? (
        <ListTable minWidth={760} striped highlightOnHover aria-label="Roles" verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Role</Table.Th>
              <Table.Th>Permissions</Table.Th>
              <Table.Th>Includes roles</Table.Th>
              <Table.Th>Managed by</Table.Th>
              {manage ? (
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              ) : null}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {roles.data.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Group gap={6}>
                    <Text fw={500}>{r.name}</Text>
                    {r.built_in ? <Tag color="gray">built-in</Tag> : null}
                  </Group>
                  <Text size="xs" c="dimmed">
                    {r.slug}
                  </Text>
                  {r.description ? (
                    <Text size="xs" c="dimmed" maw={360}>
                      {r.description}
                    </Text>
                  ) : null}
                </Table.Td>
                <Table.Td>
                  {r.permissions.length > 0 ? (
                    <Group gap={4}>
                      {r.permissions.map((p) => (
                        <Perm key={p}>{p}</Perm>
                      ))}
                    </Group>
                  ) : (
                    <Text size="sm" c="dimmed">
                      none
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>
                  <Text size="sm">
                    {r.includes.length > 0 ? r.includes.map((id) => byId.get(id)?.name ?? id).join(', ') : '—'}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <ManagedBy managedBy={r.managed_by} />
                </Table.Td>
                {manage ? (
                  <Table.Td>
                    <Group gap="xs" justify="flex-end" wrap="nowrap">
                      <Button
                        size="xs"
                        variant="default"
                        aria-label={`Edit role ${r.name}`}
                        onClick={() => {
                          setEditing({ mode: 'edit', role: r })
                        }}
                      >
                        Edit
                      </Button>
                      {r.built_in ? null : (
                        <ConfirmButton
                          variant="default"
                          label="Delete"
                          title={`Delete role ${r.name}?`}
                          confirmLabel="Delete role"
                          loading={del.isPending}
                          onConfirm={() => del.mutateAsync(r).catch(() => undefined)}
                        >
                          <Text size="sm">
                            Every assignment of <b>{r.name}</b> is removed and roles that include it no longer grant its
                            permissions. This cannot be undone.
                          </Text>
                        </ConfirmButton>
                      )}
                    </Group>
                  </Table.Td>
                ) : null}
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ListTable>
      ) : null}
      {editing && manage ? (
        <RoleDialog
          tenant={tenant}
          role={editing.mode === 'edit' ? editing.role : undefined}
          roles={roles.data ?? []}
          onClose={() => {
            setEditing(null)
          }}
        />
      ) : null}
    </>
  )
}

function RoleDialog({
  tenant,
  role,
  roles,
  onClose,
}: {
  tenant: string
  role?: Role
  roles: Role[]
  onClose: () => void
}) {
  const catalogue = useQuery(permissionsQuery(tenant))
  const [name, setName] = useState(role?.name ?? '')
  const [slug, setSlug] = useState(role?.slug ?? '')
  const [slugTouched, setSlugTouched] = useState(false)
  const [description, setDescription] = useState(role?.description ?? '')
  const [permissions, setPermissions] = useState<string[]>(role?.permissions ?? [])
  const [includes, setIncludes] = useState<string[]>(role?.includes ?? [])
  const [submitted, setSubmitted] = useState(false)
  const builtIn = role?.built_in ?? false
  const save = useAdminMutation({
    mutationFn: async () => {
      const body = { name: name.trim(), description, permissions, includes }
      if (role) {
        return conflictAware(
          (async () =>
            unwrap(
              await api.PUT('/tenants/{tenant}/roles/{role}', {
                params: { path: { tenant, role: role.id }, header: ifMatch(role.version) },
                body,
              }),
            ))(),
        )
      }
      return unwrap(
        await api.POST('/tenants/{tenant}/roles', { params: { path: { tenant } }, body: { ...body, slug } }),
      )
    },
    success: (r) => (role ? `Role ${r.name} saved` : `Role ${r.name} created`),
    invalidate: authzInvalidate(tenant),
    onSuccess: onClose,
  })
  const slugError = !role && submitted && !validSlug(slug) ? 'Lowercase letters, digits and inner hyphens' : null
  const nameError = submitted && !name.trim() ? 'Required' : null
  const others = roles.filter((r) => r.id !== role?.id).map((r) => ({ value: r.id, label: `${r.name} (${r.slug})` }))
  return (
    <Modal centered opened onClose={onClose} title={role ? `Edit role ${role.name}` : 'New role'} size="lg">
      <form
        onSubmit={(e) => {
          e.preventDefault()
          setSubmitted(true)
          if (!name.trim() || (!role && !validSlug(slug))) return
          save.mutate()
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            required
            value={name}
            error={nameError}
            maxLength={200}
            data-autofocus
            onChange={(e) => {
              const v = e.currentTarget.value
              setName(v)
              if (!role && !slugTouched) setSlug(slugify(v))
            }}
          />
          {role ? null : (
            <TextInput
              label="Slug"
              description="Stable identifier used by the API and Terraform; cannot be changed later."
              required
              value={slug}
              error={slugError}
              maxLength={63}
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
          {builtIn ? (
            <Alert color="gray" title="Built-in role">
              The permissions of built-in roles are fixed:{' '}
              {permissions.length > 0 ? permissions.map((p) => <Perm key={p}>{p}</Perm>) : 'none'}. You can still change
              its name, description and included roles.
            </Alert>
          ) : (
            <PermissionPicker
              label="Permissions"
              value={permissions}
              onChange={setPermissions}
              system={catalogue.data?.system}
              custom={catalogue.data?.custom}
            />
          )}
          {catalogue.error ? (
            <ErrorAlert error={catalogue.error} title="Could not load the permission catalogue" />
          ) : null}
          <MultiSelect
            label="Includes roles"
            description="Members of this role also get every permission of the included roles (no cycles, at most 5 levels)."
            data={others}
            value={includes}
            onChange={setIncludes}
            searchable
            clearable
            clearButtonProps={{ 'aria-label': 'Clear includes roles' }}
            nothingFoundMessage="No other roles"
          />
          <MutationError error={save.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              {role ? 'Save role' : 'Create role'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
