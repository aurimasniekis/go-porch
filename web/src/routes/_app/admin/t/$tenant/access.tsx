import {
  Alert,
  Autocomplete,
  Button,
  Card,
  Group,
  NumberInput,
  Radio,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Table,
  Tabs,
  Text,
  TextInput,
  Title,
  type ComboboxItemGroup,
} from '@mantine/core'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, can } from '@/api/admin'
import {
  applicationsQuery,
  effectiveQuery,
  memberLabel,
  mayListMembers,
  membersQuery,
  normalizeDecision,
  permissionsQuery,
  resourcesQuery,
  serviceAccountsQuery,
  type AuthzCheckRequest,
} from '@/api/admin/authz'
import { api, unwrap } from '@/api/client'
import { DecisionView } from '@/components/admin/authz/DecisionView'
import { LoadingState, Perm, Tag } from '@/components/admin/authz/common'
import { validAction } from '@/components/admin/authz/logic'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'

export const Route = createFileRoute('/_app/admin/t/$tenant/access')({
  component: AccessPage,
})

function useTenantCaps(tenant: string) {
  const caps = useQuery(adminQuery)
  const t = caps.data?.tenants.find((x) => x.slug === tenant || x.id === tenant)
  return {
    effective: can(t, 'role:manage'),
    simulate: can(t, 'authz:simulate'),
    members: mayListMembers(t),
    sas: can(t, 'service_account:manage'),
    apps: can(t, 'app:manage'),
    resources: can(t, 'resource:manage'),
    loaded: !!caps.data,
  }
}

function AccessPage() {
  const { tenant } = Route.useParams()
  const may = useTenantCaps(tenant)
  const first = may.effective ? 'effective' : 'simulator'
  return (
    <>
      <PageHeader
        title="Access explorer"
        description="See every permission that reaches a member or service account, and ask the engine whether a member may perform an action — with the full explanation."
      />
      {may.loaded && !may.effective && !may.simulate ? (
        <Alert color="gray">You need role:manage or authz:simulate in this tenant to use the access explorer.</Alert>
      ) : null}
      {may.loaded && (may.effective || may.simulate) ? (
        <Tabs defaultValue={first} keepMounted={false}>
          <Tabs.List mb="md">
            {may.effective ? <Tabs.Tab value="effective">Effective permissions</Tabs.Tab> : null}
            {may.simulate ? <Tabs.Tab value="simulator">Simulator</Tabs.Tab> : null}
          </Tabs.List>
          {may.effective ? (
            <Tabs.Panel value="effective">
              <Effective tenant={tenant} may={may} />
            </Tabs.Panel>
          ) : null}
          {may.simulate ? (
            <Tabs.Panel value="simulator">
              <Simulator tenant={tenant} may={may} />
            </Tabs.Panel>
          ) : null}
        </Tabs>
      ) : null}
    </>
  )
}

type Caps = ReturnType<typeof useTenantCaps>

function Effective({ tenant, may }: { tenant: string; may: Caps }) {
  const members = useQuery({ ...membersQuery(tenant), enabled: may.members })
  const sas = useQuery({ ...serviceAccountsQuery(tenant), enabled: may.sas })
  const [subject, setSubject] = useState<string | null>(null)
  const [type, id] = subject ? (subject.split('|') as ['user' | 'service_account', string]) : [undefined, undefined]
  const grants = useQuery({
    ...effectiveQuery(tenant, type ?? 'user', id ?? ''),
    enabled: !!type && !!id,
  })
  const data: ComboboxItemGroup[] = [
    {
      group: 'Members',
      items: (members.data ?? []).map((m) => ({ value: `user|${m.user_id}`, label: memberLabel(m) })),
    },
    {
      group: 'Service accounts',
      items: (sas.data ?? []).map((s) => ({ value: `service_account|${s.id}`, label: `${s.name} (${s.slug})` })),
    },
  ].filter((g) => g.items.length > 0)
  return (
    <Stack>
      <ErrorAlert error={members.error} title="Could not load members" />
      <ErrorAlert error={sas.error} title="Could not load service accounts" />
      {!may.members && !may.sas ? (
        <Alert color="gray">You cannot list members or service accounts in this tenant.</Alert>
      ) : null}
      <Select
        label="Subject"
        placeholder={members.isPending && may.members ? 'Loading…' : 'Search members and service accounts'}
        data={data}
        value={subject}
        onChange={setSubject}
        searchable
        clearable
        clearButtonProps={{ 'aria-label': 'Clear subject' }}
        maw={480}
        nothingFoundMessage="Nothing found"
      />
      <ErrorAlert error={grants.error} title="Could not load effective permissions" />
      {subject && grants.isPending ? <LoadingState label="Resolving grants…" /> : null}
      {!subject ? (
        <Text c="dimmed" size="sm">
          Choose a subject to list every grant that reaches it, through direct assignments, groups (including nested
          groups) and bundled roles. Conditions are listed, not evaluated — use the simulator for a decision.
        </Text>
      ) : null}
      {grants.data?.length === 0 ? <EmptyState>No grants reach this subject.</EmptyState> : null}
      {grants.data && grants.data.length > 0 ? (
        <Table.ScrollContainer minWidth={720}>
          <Table striped aria-label="Effective permissions" verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Permission</Table.Th>
                <Table.Th>Scope</Table.Th>
                <Table.Th>Role</Table.Th>
                <Table.Th>Via</Table.Th>
                <Table.Th>Limits</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {grants.data.map((g, i) => (
                <Table.Tr key={`${g.permission}|${g.scope}|${g.role}|${g.via}|${String(i)}`}>
                  <Table.Td>
                    <Perm>{g.permission}</Perm>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{g.scope}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{g.role}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{g.via}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {g.conditional ? <Tag color="violet">conditional</Tag> : null}
                      {g.expires ? <Tag color="orange">expires</Tag> : null}
                      {!g.conditional && !g.expires ? (
                        <Text size="sm" c="dimmed">
                          —
                        </Text>
                      ) : null}
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : null}
    </Stack>
  )
}

const weekdays = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function Simulator({ tenant, may }: { tenant: string; may: Caps }) {
  const members = useQuery({ ...membersQuery(tenant), enabled: may.members })
  const catalogue = useQuery({ ...permissionsQuery(tenant), enabled: may.effective })
  const apps = useQuery({ ...applicationsQuery(tenant), enabled: may.apps })
  const resources = useQuery({ ...resourcesQuery(tenant), enabled: may.resources })
  const [user, setUser] = useState<string | null>(null)
  const [action, setAction] = useState('app:access')
  const [target, setTarget] = useState<'tenant' | 'app' | 'resource'>('tenant')
  const [app, setApp] = useState<string | null>(null)
  const [resource, setResource] = useState<string | null>(null)
  const [simulate, setSimulate] = useState(false)
  const [network, setNetwork] = useState<string | null>('trusted')
  const [hour, setHour] = useState<number | string>(new Date().getUTCHours())
  const [weekday, setWeekday] = useState<string | null>(weekdays[(new Date().getUTCDay() + 6) % 7] ?? 'Mon')
  const [ip, setIp] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const checkMut = useMutation({
    mutationFn: async (body: AuthzCheckRequest) =>
      normalizeDecision(
        unwrap(await api.POST('/tenants/{tenant}/authz/check', { params: { path: { tenant } }, body })),
      ),
  })
  const errors = {
    user: !user ? 'Choose a member' : null,
    action: !validAction(action) ? 'A concrete permission such as app:access (no wildcards)' : null,
    app: target === 'app' && !app ? 'Choose an application' : null,
    resource: target === 'resource' && !resource ? 'Choose a resource' : null,
    hour: simulate && (typeof hour !== 'number' || hour < 0 || hour > 23) ? 'An hour between 0 and 23' : null,
  }
  const actions = [...(catalogue.data?.system ?? ['app:access']), ...(catalogue.data?.custom ?? [])].filter(
    (p) => !p.includes('*'),
  )
  return (
    <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="lg">
      <Card>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            setSubmitted(true)
            if (Object.values(errors).some(Boolean) || !user) return
            const body: AuthzCheckRequest = { user_id: user, action, resource: { type: 'tenant' } }
            if (target === 'app' && app) body.resource = { type: 'app', id: app }
            if (target === 'resource' && resource) {
              const r = (resources.data ?? []).find((x) => x.id === resource)
              if (r) body.resource = { type: r.type, id: r.id }
            }
            if (simulate) {
              body.context = {
                tenant,
                network: network ?? 'external',
                hour: typeof hour === 'number' ? hour : 0,
                weekday: weekday ?? 'Mon',
                ...(ip.trim() ? { ip: ip.trim() } : {}),
              }
            }
            checkMut.mutate(body)
          }}
        >
          <Stack>
            <Title order={2} size="h4">
              Ask the engine
            </Title>
            <ErrorAlert error={members.error} title="Could not load members" />
            {!may.members ? <Alert color="gray">You cannot list the members of this tenant.</Alert> : null}
            <Select
              label="Member"
              placeholder={members.isPending && may.members ? 'Loading…' : 'Search members'}
              required
              data={(members.data ?? []).map((m) => ({ value: m.user_id, label: memberLabel(m) }))}
              value={user}
              onChange={setUser}
              searchable
              error={submitted ? errors.user : null}
              nothingFoundMessage="Nothing found"
            />
            <Autocomplete
              label="Action"
              description="The permission to check, <type>:<action>."
              required
              data={actions}
              value={action}
              onChange={setAction}
              error={submitted ? errors.action : null}
            />
            <Radio.Group
              label="Resource"
              value={target}
              onChange={(v) => {
                setTarget(v as 'tenant' | 'app' | 'resource')
              }}
            >
              <Group mt={6}>
                <Radio value="tenant" label="The tenant" />
                <Radio value="app" label="An application" disabled={!may.apps} />
                <Radio value="resource" label="A resource" disabled={!may.resources} />
              </Group>
            </Radio.Group>
            {target === 'app' ? (
              <Select
                label="Application"
                required
                data={(apps.data ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.slug})` }))}
                value={app}
                onChange={setApp}
                searchable
                error={submitted ? errors.app : null}
                nothingFoundMessage="No applications"
              />
            ) : null}
            {target === 'resource' ? (
              <Select
                label="Resource"
                required
                data={(resources.data ?? []).map((r) => ({ value: r.id, label: `${r.name} (${r.type}/${r.slug})` }))}
                value={resource}
                onChange={setResource}
                searchable
                error={submitted ? errors.resource : null}
                nothingFoundMessage="No resources"
              />
            ) : null}
            <Switch
              label="Simulate request context"
              description="Evaluate policies as if the request came from this network, time and IP (flagged as simulated in the trace)."
              checked={simulate}
              onChange={(e) => {
                setSimulate(e.currentTarget.checked)
              }}
            />
            {simulate ? (
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <Select
                  label="Network"
                  data={[
                    { value: 'trusted', label: 'trusted' },
                    { value: 'external', label: 'external' },
                  ]}
                  value={network}
                  onChange={setNetwork}
                  allowDeselect={false}
                />
                <TextInput
                  label="IP address (optional)"
                  value={ip}
                  placeholder="203.0.113.10"
                  onChange={(e) => {
                    setIp(e.currentTarget.value)
                  }}
                />
                <NumberInput
                  label="Hour (UTC)"
                  min={0}
                  max={23}
                  allowDecimal={false}
                  value={hour}
                  onChange={setHour}
                  error={submitted ? errors.hour : null}
                />
                <Select
                  label="Weekday (UTC)"
                  data={weekdays}
                  value={weekday}
                  onChange={setWeekday}
                  allowDeselect={false}
                />
              </SimpleGrid>
            ) : null}
            <ErrorAlert error={checkMut.error} title="Check failed" />
            <Group>
              <Button type="submit" loading={checkMut.isPending}>
                Check access
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>
      <div aria-live="polite">
        {checkMut.data ? (
          <DecisionView decision={checkMut.data} />
        ) : (
          <Text c="dimmed" size="sm">
            The decision and its explanation (tenant gate, groups, candidate grants with condition results, deny
            policies and context) appear here.
          </Text>
        )}
      </div>
    </SimpleGrid>
  )
}
