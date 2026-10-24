import {
  Alert,
  Autocomplete,
  Button,
  Group,
  Radio,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  type ComboboxItemGroup,
  Modal,
} from '@mantine/core'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, can, useAdminMutation } from '@/api/admin'
import {
  applicationsQuery,
  assignmentsQuery,
  authzInvalidate,
  groupsQuery,
  memberLabel,
  mayListMembers,
  membersQuery,
  policiesQuery,
  resourcesQuery,
  rolesQuery,
  serviceAccountsQuery,
  type Assignment,
  type AssignmentRequest,
} from '@/api/admin/authz'
import { api, check, unwrap } from '@/api/client'
import { LoadingState, MutationError, Tag } from '@/components/admin/authz/common'
import { localInputToISO, scopeText, toLocalInput, validResourceType } from '@/components/admin/authz/logic'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'

export const Route = createFileRoute('/_app/admin/t/$tenant/assignments')({
  component: AssignmentsPage,
})

type SubjectType = AssignmentRequest['subject_type']
type ScopeType = AssignmentRequest['scope_type']

const subjectTypeLabel: Record<string, string> = { user: 'Member', group: 'Group', service_account: 'Service account' }
const subjectTypeColor: Record<string, string> = { user: 'violet', group: 'teal', service_account: 'orange' }

/** Loads everything needed to name subjects, roles, scopes and conditions — only what the caller may list. */
function useDirectory(tenant: string) {
  const caps = useQuery(adminQuery)
  const t = caps.data?.tenants.find((x) => x.slug === tenant || x.id === tenant)
  const may = {
    members: mayListMembers(t),
    groups: can(t, 'group:manage'),
    sas: can(t, 'service_account:manage'),
    policies: can(t, 'policy:manage'),
    resources: can(t, 'resource:manage'),
    apps: can(t, 'app:manage'),
  }
  const roles = useQuery(rolesQuery(tenant))
  const members = useQuery({ ...membersQuery(tenant), enabled: may.members })
  const groups = useQuery({ ...groupsQuery(tenant), enabled: may.groups })
  const sas = useQuery({ ...serviceAccountsQuery(tenant), enabled: may.sas })
  const policies = useQuery({ ...policiesQuery(tenant), enabled: may.policies })
  const resources = useQuery({ ...resourcesQuery(tenant), enabled: may.resources })
  const apps = useQuery({ ...applicationsQuery(tenant), enabled: may.apps })
  const subjects = new Map<string, string>()
  for (const m of members.data ?? []) subjects.set(`user:${m.user_id}`, memberLabel(m))
  for (const g of groups.data ?? []) subjects.set(`group:${g.id}`, g.name)
  for (const s of sas.data ?? []) subjects.set(`service_account:${s.id}`, s.name)
  const scopeNames = new Map<string, string>()
  for (const a of apps.data ?? []) scopeNames.set(`app:${a.id}`, a.name)
  for (const r of resources.data ?? []) scopeNames.set(`${r.type}:${r.id}`, r.name)
  return {
    may,
    roles,
    members,
    groups,
    sas,
    policies,
    resources,
    apps,
    subjects,
    scopeNames,
    roleById: new Map((roles.data ?? []).map((r) => [r.id, r])),
    policyById: new Map((policies.data ?? []).map((p) => [p.id, p])),
  }
}

type Directory = ReturnType<typeof useDirectory>

function AssignmentsPage() {
  const { tenant } = Route.useParams()
  const dir = useDirectory(tenant)
  const assignments = useQuery(assignmentsQuery(tenant))
  const [creating, setCreating] = useState(false)
  const [subjectFilter, setSubjectFilter] = useState<string | null>(null)
  const [roleFilter, setRoleFilter] = useState<string | null>(null)
  const del = useAdminMutation({
    mutationFn: async (a: Assignment) => {
      check(
        await api.DELETE('/tenants/{tenant}/assignments/{assignment}', {
          params: { path: { tenant, assignment: a.id } },
        }),
      )
    },
    success: 'Assignment removed',
    invalidate: authzInvalidate(tenant),
  })
  const all = assignments.data ?? []
  const subjectName = (a: Assignment) => dir.subjects.get(`${a.subject_type}:${a.subject_id}`) ?? a.subject_id
  const rows = all.filter(
    (a) =>
      (!subjectFilter || `${a.subject_type}:${a.subject_id}` === subjectFilter) &&
      (!roleFilter || a.role_id === roleFilter),
  )
  const subjectOptions = [...new Set(all.map((a) => `${a.subject_type}:${a.subject_id}`))].map((k) => {
    const [type, ...rest] = k.split(':')
    return {
      value: k,
      label: `${dir.subjects.get(k) ?? rest.join(':')} (${(subjectTypeLabel[type] ?? type).toLowerCase()})`,
    }
  })
  const roleOptions = (dir.roles.data ?? []).map((r) => ({ value: r.id, label: r.name }))
  return (
    <>
      <PageHeader
        title="Assignments"
        description="An assignment grants a role to a member, group or service account across the tenant, for one resource type, or for a single resource — optionally only while a condition policy holds, and optionally until a date."
        actions={
          <Button
            leftSection={<IconPlus size={16} aria-hidden />}
            onClick={() => {
              setCreating(true)
            }}
          >
            New assignment
          </Button>
        }
      />
      <ErrorAlert error={assignments.error} title="Could not load assignments" />
      <ErrorAlert error={dir.roles.error} title="Could not load roles" />
      <Group mb="md" align="flex-end">
        <Select
          label="Filter by subject"
          placeholder="All subjects"
          data={subjectOptions}
          value={subjectFilter}
          onChange={setSubjectFilter}
          searchable
          clearable
          clearButtonProps={{ 'aria-label': 'Clear filter by subject' }}
          w={{ base: '100%', sm: 300 }}
        />
        <Select
          label="Filter by role"
          placeholder="All roles"
          data={roleOptions}
          value={roleFilter}
          onChange={setRoleFilter}
          searchable
          clearable
          clearButtonProps={{ 'aria-label': 'Clear filter by role' }}
          w={{ base: '100%', sm: 240 }}
        />
      </Group>
      {assignments.isPending ? <LoadingState label="Loading assignments…" /> : null}
      {assignments.data && rows.length === 0 ? (
        <EmptyState>{all.length === 0 ? 'No assignments yet.' : 'No assignments match the filters.'}</EmptyState>
      ) : null}
      {rows.length > 0 ? (
        <Table.ScrollContainer minWidth={900}>
          <Table striped highlightOnHover aria-label="Role assignments" verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Subject</Table.Th>
                <Table.Th>Role</Table.Th>
                <Table.Th>Scope</Table.Th>
                <Table.Th>Condition</Table.Th>
                <Table.Th>Expires</Table.Th>
                <Table.Th>Source</Table.Th>
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((a) => {
                const role = dir.roleById.get(a.role_id)
                const pol = a.condition_policy_id ? dir.policyById.get(a.condition_policy_id) : undefined
                const expired = a.expires_at ? new Date(a.expires_at) <= new Date() : false
                return (
                  <Table.Tr key={a.id}>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <Tag color={subjectTypeColor[a.subject_type] ?? 'gray'}>
                          {subjectTypeLabel[a.subject_type] ?? a.subject_type}
                        </Tag>
                        <Text size="sm">{subjectName(a)}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{role?.name ?? a.role_id}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">
                        {scopeText(
                          a.scope_type,
                          a.scope_resource_type,
                          a.scope_resource_id
                            ? (dir.scopeNames.get(`${a.scope_resource_type ?? ''}:${a.scope_resource_id}`) ??
                                a.scope_resource_id)
                            : undefined,
                        )}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      {a.condition_policy_id ? (
                        <Text size="sm">{pol?.name ?? a.condition_policy_id}</Text>
                      ) : (
                        <Text size="sm" c="dimmed">
                          always
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      {a.expires_at ? (
                        <Group gap={6} wrap="nowrap">
                          <Text size="sm">{new Date(a.expires_at).toLocaleString()}</Text>
                          {expired ? <Tag color="red">expired</Tag> : null}
                        </Group>
                      ) : (
                        <Text size="sm" c="dimmed">
                          never
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{a.source}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Group justify="flex-end">
                        <ConfirmButton
                          variant="default"
                          label="Remove"
                          title="Remove this assignment?"
                          confirmLabel="Remove assignment"
                          loading={del.isPending}
                          onConfirm={() => del.mutateAsync(a).catch(() => undefined)}
                        >
                          <Text size="sm">
                            {subjectName(a)} loses the role {role?.name ?? a.role_id} granted by this assignment.
                          </Text>
                        </ConfirmButton>
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                )
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : null}
      {creating ? (
        <AssignmentDialog
          tenant={tenant}
          dir={dir}
          onClose={() => {
            setCreating(false)
          }}
        />
      ) : null}
    </>
  )
}

function AssignmentDialog({ tenant, dir, onClose }: { tenant: string; dir: Directory; onClose: () => void }) {
  const [subjectType, setSubjectType] = useState<SubjectType>('user')
  const [subject, setSubject] = useState<string | null>(null)
  const [role, setRole] = useState<string | null>(null)
  const [scope, setScope] = useState<ScopeType>('tenant')
  const [resourceType, setResourceType] = useState('')
  const [resource, setResource] = useState<string | null>(null)
  const [condition, setCondition] = useState<string | null>(null)
  const [expires, setExpires] = useState('')
  const [submitted, setSubmitted] = useState(false)

  const subjectData: Record<SubjectType, { value: string; label: string }[]> = {
    user: (dir.members.data ?? []).map((m) => ({ value: m.user_id, label: memberLabel(m) })),
    group: (dir.groups.data ?? []).map((g) => ({ value: g.id, label: `${g.name} (${g.slug})` })),
    service_account: (dir.sas.data ?? []).map((s) => ({ value: s.id, label: `${s.name} (${s.slug})` })),
  }
  const subjectAllowed: Record<SubjectType, boolean> = {
    user: dir.may.members,
    group: dir.may.groups,
    service_account: dir.may.sas,
  }
  const resourceGroups: ComboboxItemGroup[] = [
    {
      group: 'Applications',
      items: (dir.apps.data ?? []).map((a) => ({ value: `app:${a.id}`, label: `${a.name} (${a.slug})` })),
    },
    {
      group: 'Resources',
      items: (dir.resources.data ?? []).map((r) => ({
        value: `${r.type}:${r.id}`,
        label: `${r.name} (${r.type}/${r.slug})`,
      })),
    },
  ].filter((g) => g.items.length > 0)
  const knownTypes = [...new Set(['app', ...(dir.resources.data ?? []).map((r) => r.type)])].sort()
  const conditions = (dir.policies.data ?? [])
    .filter((p) => p.effect === 'condition')
    .map((p) => ({ value: p.id, label: `${p.name} (${p.slug})` }))
  const expiresISO = localInputToISO(expires)
  const expiresError =
    expires && (!expiresISO || new Date(expiresISO) <= new Date()) ? 'Must be a date and time in the future' : null

  const errors = {
    subject: !subject ? 'Choose a subject' : null,
    role: !role ? 'Choose a role' : null,
    resourceType: scope === 'resource_type' && !validResourceType(resourceType) ? 'A lowercase resource type' : null,
    resource: scope === 'resource' && !resource ? 'Choose an application or resource' : null,
  }
  const valid = !Object.values(errors).some(Boolean) && !expiresError

  const create = useAdminMutation({
    mutationFn: async (body: AssignmentRequest) =>
      unwrap(await api.POST('/tenants/{tenant}/assignments', { params: { path: { tenant } }, body })),
    success: 'Role assigned',
    invalidate: authzInvalidate(tenant),
    onSuccess: onClose,
  })

  const submit = () => {
    setSubmitted(true)
    if (!valid || !subject || !role) return
    const body: AssignmentRequest = { subject_type: subjectType, subject_id: subject, role_id: role, scope_type: scope }
    if (scope === 'resource_type') body.scope_resource_type = resourceType
    if (scope === 'resource' && resource) {
      const i = resource.indexOf(':')
      body.scope_resource_type = resource.slice(0, i)
      body.scope_resource_id = resource.slice(i + 1)
    }
    if (condition) body.condition_policy_id = condition
    if (expiresISO) body.expires_at = expiresISO
    create.mutate(body)
  }

  return (
    <Modal centered opened onClose={onClose} title="New assignment" size="lg">
      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <Stack>
          <Radio.Group
            label="Subject type"
            value={subjectType}
            onChange={(v) => {
              setSubjectType(v as SubjectType)
              setSubject(null)
            }}
          >
            <Group mt={6}>
              <Radio value="user" label="Member" />
              <Radio value="group" label="Group" />
              <Radio value="service_account" label="Service account" />
            </Group>
          </Radio.Group>
          {subjectAllowed[subjectType] ? null : (
            <Alert color="gray">You do not have permission to list these subjects in this tenant.</Alert>
          )}
          <Select
            label={subjectTypeLabel[subjectType]}
            placeholder="Search"
            required
            data={subjectData[subjectType]}
            value={subject}
            onChange={setSubject}
            searchable
            disabled={!subjectAllowed[subjectType]}
            error={submitted ? errors.subject : null}
            nothingFoundMessage="Nothing found"
          />
          <Select
            label="Role"
            placeholder="Choose a role"
            required
            data={(dir.roles.data ?? []).map((r) => ({ value: r.id, label: `${r.name} (${r.slug})` }))}
            value={role}
            onChange={setRole}
            searchable
            error={submitted ? errors.role : null}
          />
          <Radio.Group
            label="Scope"
            value={scope}
            onChange={(v) => {
              setScope(v as ScopeType)
            }}
          >
            <Group mt={6}>
              <Radio value="tenant" label="Whole tenant" />
              <Radio value="resource_type" label="Resource type" />
              <Radio value="resource" label="Specific resource" />
            </Group>
          </Radio.Group>
          {scope === 'resource_type' ? (
            <Autocomplete
              label="Resource type"
              description="Applications are type app."
              required
              data={knownTypes}
              value={resourceType}
              onChange={setResourceType}
              error={submitted ? errors.resourceType : null}
            />
          ) : null}
          {scope === 'resource' ? (
            <Select
              label="Application or resource"
              placeholder={!dir.may.apps && !dir.may.resources ? 'You cannot list applications or resources' : 'Search'}
              required
              data={resourceGroups}
              value={resource}
              onChange={setResource}
              searchable
              disabled={!dir.may.apps && !dir.may.resources}
              error={submitted ? errors.resource : null}
              nothingFoundMessage="Nothing found"
            />
          ) : null}
          <Select
            label="Condition policy (optional)"
            description={
              dir.may.policies
                ? 'The assignment only applies while this condition policy evaluates to true.'
                : 'Choosing a condition needs the policy:manage permission.'
            }
            placeholder="Always applies"
            data={conditions}
            value={condition}
            onChange={setCondition}
            clearable
            clearButtonProps={{ 'aria-label': 'Clear condition policy' }}
            disabled={!dir.may.policies}
          />
          <TextInput
            type="datetime-local"
            label="Expires at (optional)"
            description="In your local time zone. Leave empty for an assignment that does not expire."
            value={expires}
            min={toLocalInput(new Date())}
            onChange={(e) => {
              setExpires(e.currentTarget.value)
            }}
            error={expiresError}
          />
          <MutationError error={create.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Assign role
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
