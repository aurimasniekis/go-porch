import { Autocomplete, Box, Button, Code, Group, Select, Stack, Table, Text, TextInput, Modal } from '@mantine/core'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { can, ifMatch, useAdminMutation, useAdminTenant } from '@/api/admin'
import { authzInvalidate, conflictAware, resourcesQuery, type ResourceDef } from '@/api/admin/authz'
import { api, check, unwrap } from '@/api/client'
import { LoadingState, ManagedBy, MutationError, Tag } from '@/components/admin/authz/common'
import { AttributesEditor } from '@/components/admin/authz/inputs'
import {
  attributesToRows,
  descendantIds,
  flattenTree,
  rowsToAttributes,
  slugify,
  validResourceType,
  validSlug,
  type AttributeRow,
} from '@/components/admin/authz/logic'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader, ReadOnlyNote } from '@/components/admin/kit'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/t/$tenant/resources')({
  component: ResourcesPage,
})

const byTypeThenName = (a: ResourceDef, b: ResourceDef) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name)

type OpenDialog = { kind: 'create' } | { kind: 'edit'; resource: ResourceDef } | null

function ResourcesPage() {
  const { tenant } = Route.useParams()
  const resources = useQuery(resourcesQuery(tenant))
  const manage = can(useAdminTenant(tenant), 'resource:manage')
  const [dialog, setDialog] = useState<OpenDialog>(null)
  const del = useAdminMutation({
    mutationFn: async (r: ResourceDef) => {
      check(
        await api.DELETE('/tenants/{tenant}/resources/{resource}', { params: { path: { tenant, resource: r.id } } }),
      )
    },
    success: 'Resource deleted',
    invalidate: authzInvalidate(tenant),
  })
  const list = resources.data ?? []
  const flat = flattenTree(list, byTypeThenName)
  const byId = new Map(list.map((r) => [r.id, r]))
  return (
    <>
      <PageHeader
        title="Resources"
        description="Resources are things your applications protect (documents, projects, environments…). Assignments can be scoped to a resource type or to one resource; a grant on a resource also covers the resources below it. Applications are resources of type app automatically."
        actions={
          manage ? (
            <Button
              leftSection={<IconPlus size={16} aria-hidden />}
              onClick={() => {
                setDialog({ kind: 'create' })
              }}
            >
              New resource
            </Button>
          ) : null
        }
      />
      {manage ? null : <ReadOnlyNote what="resources" />}
      <ErrorAlert error={resources.error} title="Could not load resources" />
      {resources.isPending ? <LoadingState label="Loading resources…" /> : null}
      {resources.data?.length === 0 ? <EmptyState>No resources yet.</EmptyState> : null}
      {flat.length > 0 ? (
        <ListTable
          minWidth={760}
          striped
          highlightOnHover
          aria-label="Resources (indented by parent)"
          verticalSpacing="sm"
        >
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Type</Table.Th>
              <Table.Th>Slug</Table.Th>
              <Table.Th>Attributes</Table.Th>
              <Table.Th>Managed by</Table.Th>
              {manage ? (
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              ) : null}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {flat.map(({ item: r, depth, descendants }) => {
              const attrs = Object.entries(r.attributes).sort(([a], [b]) => a.localeCompare(b))
              const parent = r.parent_id ? byId.get(r.parent_id) : undefined
              return (
                <Table.Tr key={r.id}>
                  <Table.Td>
                    <Box pl={depth * 20}>
                      <Group gap={6} wrap="nowrap">
                        {depth > 0 ? (
                          <Text c="dimmed" aria-hidden>
                            └
                          </Text>
                        ) : null}
                        <div>
                          <Text fw={500}>{r.name}</Text>
                          {parent ? (
                            <Text size="xs" c="dimmed">
                              in {parent.name}
                            </Text>
                          ) : null}
                        </div>
                      </Group>
                    </Box>
                  </Table.Td>
                  <Table.Td>
                    <Tag color="cyan">{r.type}</Tag>
                  </Table.Td>
                  <Table.Td>
                    <Code>{r.slug}</Code>
                  </Table.Td>
                  <Table.Td>
                    {attrs.length > 0 ? (
                      <Group gap={4}>
                        {attrs.map(([k, v]) => (
                          <Code key={k}>
                            {k}={v}
                          </Code>
                        ))}
                      </Group>
                    ) : (
                      <Text size="sm" c="dimmed">
                        —
                      </Text>
                    )}
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
                          aria-label={`Edit resource ${r.name}`}
                          onClick={() => {
                            setDialog({ kind: 'edit', resource: r })
                          }}
                        >
                          Edit
                        </Button>
                        <ConfirmButton
                          variant="default"
                          label="Delete"
                          title={`Delete resource ${r.name}?`}
                          confirmLabel="Delete resource"
                          loading={del.isPending}
                          onConfirm={() => del.mutateAsync(r).catch(() => undefined)}
                        >
                          <Stack gap="xs">
                            <Text size="sm">
                              Every assignment scoped to <b>{r.name}</b> is removed.
                            </Text>
                            {descendants > 0 ? (
                              <Text size="sm" fw={600}>
                                Its {descendants} child resource{descendants > 1 ? 's are' : ' is'} deleted too, with
                                their assignments.
                              </Text>
                            ) : null}
                            <Text size="sm">This cannot be undone.</Text>
                          </Stack>
                        </ConfirmButton>
                      </Group>
                    </Table.Td>
                  ) : null}
                </Table.Tr>
              )
            })}
          </Table.Tbody>
        </ListTable>
      ) : null}
      {dialog && manage ? (
        <ResourceDialog
          tenant={tenant}
          resources={list}
          resource={dialog.kind === 'edit' ? dialog.resource : undefined}
          onClose={() => {
            setDialog(null)
          }}
        />
      ) : null}
    </>
  )
}

function ResourceDialog({
  tenant,
  resources,
  resource,
  onClose,
}: {
  tenant: string
  resources: ResourceDef[]
  resource?: ResourceDef
  onClose: () => void
}) {
  const [type, setType] = useState(resource?.type ?? '')
  const [slug, setSlug] = useState(resource?.slug ?? '')
  const [slugTouched, setSlugTouched] = useState(false)
  const [name, setName] = useState(resource?.name ?? '')
  const [parent, setParent] = useState<string | null>(resource?.parent_id ?? null)
  const [rows, setRows] = useState<AttributeRow[]>(attributesToRows(resource?.attributes))
  const [submitted, setSubmitted] = useState(false)
  const attrs = rowsToAttributes(rows)
  const typeError =
    !resource && submitted && (!validResourceType(type) || type === 'app' || type === 'tenant')
      ? 'Lowercase identifier (letters, digits, _); app and tenant are reserved'
      : null
  const slugError = !resource && submitted && !validSlug(slug) ? 'Lowercase letters, digits and inner hyphens' : null
  const nameError = submitted && !name.trim() ? 'Required' : null
  const save = useAdminMutation({
    mutationFn: async () => {
      if (resource) {
        return conflictAware(
          (async () =>
            unwrap(
              await api.PATCH('/tenants/{tenant}/resources/{resource}', {
                params: { path: { tenant, resource: resource.id }, header: ifMatch(resource.version) },
                body: { name: name.trim(), attributes: attrs.attributes },
              }),
            ))(),
        )
      }
      return unwrap(
        await api.POST('/tenants/{tenant}/resources', {
          params: { path: { tenant } },
          body: {
            type,
            slug,
            name: name.trim(),
            attributes: attrs.attributes,
            ...(parent ? { parent_id: parent } : {}),
          },
        }),
      )
    },
    success: (r) => (resource ? `Resource ${r.name} saved` : `Resource ${r.name} created`),
    invalidate: authzInvalidate(tenant),
    onSuccess: onClose,
  })
  const exclude = resource ? descendantIds(resources, resource.id) : new Set<string>()
  const parentOptions = flattenTree(resources, byTypeThenName)
    .filter(({ item }) => item.id !== resource?.id && !exclude.has(item.id))
    .map(({ item, depth }) => ({
      value: item.id,
      label: `${'· '.repeat(depth)}${item.name} (${item.type}/${item.slug})`,
    }))
  const types = [...new Set(resources.map((r) => r.type))].sort()
  return (
    <Modal
      centered
      opened
      onClose={onClose}
      title={resource ? `Edit resource ${resource.name}` : 'New resource'}
      size="lg"
    >
      <form
        onSubmit={(e) => {
          e.preventDefault()
          setSubmitted(true)
          if (attrs.error || !name.trim()) return
          if (!resource && (!validResourceType(type) || type === 'app' || type === 'tenant' || !validSlug(slug))) return
          save.mutate()
        }}
      >
        <Stack>
          {resource ? (
            <Text size="sm">
              Type <Code>{resource.type}</Code>, slug <Code>{resource.slug}</Code>
              {resource.parent_id
                ? ' — type, slug and parent cannot be changed.'
                : ' — type and slug cannot be changed.'}
            </Text>
          ) : (
            <>
              <Autocomplete
                label="Type"
                description="For example doc, project or environment. Permissions use it as <type>:<action>."
                required
                data-autofocus
                data={types}
                value={type}
                onChange={setType}
                error={typeError}
                maxLength={32}
              />
              <TextInput
                label="Name"
                required
                value={name}
                maxLength={200}
                error={nameError}
                onChange={(e) => {
                  const v = e.currentTarget.value
                  setName(v)
                  if (!slugTouched) setSlug(slugify(v))
                }}
              />
              <TextInput
                label="Slug"
                description="Unique per type; visible to policies as resource.slug."
                required
                value={slug}
                maxLength={63}
                error={slugError}
                onChange={(e) => {
                  setSlugTouched(true)
                  setSlug(e.currentTarget.value)
                }}
              />
              <Select
                label="Parent resource (optional)"
                description="Grants on the parent also cover this resource (at most 5 levels)."
                placeholder="None (top level)"
                data={parentOptions}
                value={parent}
                onChange={setParent}
                searchable
                clearable
                clearButtonProps={{ 'aria-label': 'Clear parent resource' }}
                nothingFoundMessage="No resources"
              />
            </>
          )}
          {resource ? (
            <TextInput
              label="Name"
              required
              data-autofocus
              value={name}
              maxLength={200}
              error={nameError}
              onChange={(e) => {
                setName(e.currentTarget.value)
              }}
            />
          ) : null}
          <AttributesEditor rows={rows} onChange={setRows} error={submitted ? attrs.error : null} />
          <MutationError error={save.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              {resource ? 'Save resource' : 'Create resource'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
