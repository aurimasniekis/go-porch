import { Button, Card, Group, Select, SimpleGrid, Stack, Table, Text, TextInput, VisuallyHidden } from '@mantine/core'
import { useForm } from '@mantine/form'
import { IconAlertTriangle } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { readsInstallationConfig, useAdminMutation, useAdminTenant } from '@/api/admin'
import {
  createDomainRule,
  deleteDomainRule,
  domainRulesQuery,
  providersQuery,
  tenantKeys,
  when,
  type CreateDomainRuleRequest,
  type DomainRule,
  type IdentityProvider,
} from '@/api/admin/tenant'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader, ReadOnlyNote } from '@/components/admin/kit'
import { LoadingRows, MutationError, Section, Notice, ProvenanceTag, Tag } from '@/components/admin/tenant/common'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/t/$tenant/domains')({
  component: DomainsPage,
})

const evidence = [
  { value: 'workspace_hd', label: 'Google Workspace domain (hd claim)' },
  { value: 'verified_email', label: 'Verified email domain' },
]
const modes = [
  { value: 'jit', label: 'Join on first sign-in (JIT)' },
  { value: 'invite_only', label: 'Invitation required' },
]

function DomainsPage() {
  const { tenant } = Route.useParams()
  const t = useAdminTenant(tenant)
  const manage = t?.via === 'operator'
  return (
    <Stack gap="xl">
      <PageHeader
        title="Domain rules"
        description="Enroll everyone who signs in with an account from a domain. Domain rules are installation-wide (a domain belongs to one tenant), so only installation operators manage them. Creating and deleting rules needs a recent sign-in."
      />
      {!readsInstallationConfig(t) ? (
        <Notice color="gray" title="Installation operators only">
          Ask an installation owner or administrator to change domain rules for this tenant.
        </Notice>
      ) : (
        <>
          {manage ? <CreateRule tenant={tenant} /> : <ReadOnlyNote what="domain rules" mb={0} />}
          <RuleList tenant={tenant} manage={manage} />
        </>
      )}
    </Stack>
  )
}

function RuleList({ tenant, manage }: { tenant: string; manage: boolean }) {
  const q = useQuery(domainRulesQuery(tenant))
  const providers = useQuery(providersQuery)
  const byId = new Map((providers.data ?? []).map((p) => [p.id, p]))
  return (
    <Section title="Rules">
      {q.error ? <ErrorAlert error={q.error} /> : null}
      {q.isPending ? (
        <LoadingRows />
      ) : !q.data?.length ? (
        q.error ? null : (
          <EmptyState>No domain rules. Members join through invitations or manual addition only.</EmptyState>
        )
      ) : (
        <ListTable minWidth={760} striped aria-label="Domain rules">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Domain</Table.Th>
              <Table.Th>Provider</Table.Th>
              <Table.Th>Evidence</Table.Th>
              <Table.Th>Mode</Table.Th>
              <Table.Th>Managed by</Table.Th>
              <Table.Th>Created</Table.Th>
              {manage ? (
                <Table.Th>
                  <VisuallyHidden>Actions</VisuallyHidden>
                </Table.Th>
              ) : null}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data.map((r) => (
              <RuleRow key={r.id} tenant={tenant} rule={r} provider={byId.get(r.provider_id)} manage={manage} />
            ))}
          </Table.Tbody>
        </ListTable>
      )}
    </Section>
  )
}

function RuleRow({
  tenant,
  rule,
  provider,
  manage,
}: {
  tenant: string
  rule: DomainRule
  provider?: IdentityProvider
  manage: boolean
}) {
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" fw={500}>
          {rule.domain}
        </Text>
      </Table.Td>
      <Table.Td>
        <Text size="sm">{provider?.name ?? rule.provider_id}</Text>
      </Table.Td>
      <Table.Td>
        {rule.evidence_kind === 'workspace_hd' ? (
          <Tag variant="light" color="green">
            Workspace hd
          </Tag>
        ) : (
          <Tag variant="light" color="orange" leftSection={<IconAlertTriangle size={12} aria-hidden />}>
            Verified email (weaker)
          </Tag>
        )}
      </Table.Td>
      <Table.Td>
        <Text size="sm">{rule.mode === 'jit' ? 'JIT' : 'Invitation required'}</Text>
      </Table.Td>
      <Table.Td>
        <ProvenanceTag managedBy={rule.managed_by} lastChangedBy={rule.last_changed_by} />
      </Table.Td>
      <Table.Td>
        <Text size="sm">{when(rule.created_at)}</Text>
      </Table.Td>
      {manage ? <RuleActions tenant={tenant} rule={rule} /> : null}
    </Table.Tr>
  )
}

function RuleActions({ tenant, rule }: { tenant: string; rule: DomainRule }) {
  const del = useAdminMutation({
    mutationFn: () => deleteDomainRule(tenant, rule),
    success: `Rule for ${rule.domain} deleted`,
    invalidate: [tenantKeys.domainRules(tenant), tenantKeys.members(tenant)],
  })
  return (
    <Table.Td>
      <Group justify="flex-end">
        <ConfirmButton
          variant="default"
          label="Delete"
          title={`Delete the rule for ${rule.domain}?`}
          loading={del.isPending}
          onConfirm={() => del.mutateAsync().catch(() => undefined)}
        >
          <Text size="sm">
            Memberships created by this rule are removed too: people from {rule.domain} lose access unless they were
            added another way. This needs a recent sign-in.
          </Text>
        </ConfirmButton>
      </Group>
    </Table.Td>
  )
}

function CreateRule({ tenant }: { tenant: string }) {
  const providers = useQuery(providersQuery)
  const form = useForm<CreateDomainRuleRequest>({
    initialValues: { domain: '', provider_id: '', evidence_kind: 'workspace_hd', mode: 'jit' },
    validate: {
      domain: (v) => (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v.trim()) ? null : 'Enter a domain like example.com'),
      provider_id: (v) => (v ? null : 'Choose an identity provider'),
    },
  })
  const create = useAdminMutation({
    mutationFn: (v: CreateDomainRuleRequest) =>
      createDomainRule(tenant, { ...v, domain: v.domain.trim().toLowerCase() }),
    success: (r) => `Rule for ${r.domain} created`,
    invalidate: [tenantKeys.domainRules(tenant)],
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
          <Section title="New rule">
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput label="Domain" placeholder="example.com" required {...form.getInputProps('domain')} />
              <Select
                label="Identity provider"
                placeholder={providers.isPending ? 'Loading…' : 'Choose a provider'}
                required
                data={(providers.data ?? []).map((p) => ({ value: p.id, label: `${p.name} (${p.kind})` }))}
                error={providers.error ? 'Could not load identity providers' : undefined}
                {...form.getInputProps('provider_id')}
              />
              <Select
                label="Evidence"
                description="What proves an account belongs to the domain"
                data={evidence}
                allowDeselect={false}
                {...form.getInputProps('evidence_kind')}
              />
              <Select label="Mode" data={modes} allowDeselect={false} {...form.getInputProps('mode')} />
            </SimpleGrid>
          </Section>
          {form.values.evidence_kind === 'verified_email' ? (
            <Notice color="orange" icon={<IconAlertTriangle size={18} />} title="Weaker evidence">
              A verified email only shows the provider confirmed the address once; anyone who can get an address at this
              domain (including consumer accounts on a shared domain) qualifies. Prefer Workspace hd evidence, which
              Google ties to an organisation-managed account.
            </Notice>
          ) : null}
          <MutationError error={create.error} />
          <Group justify="flex-end">
            <Button type="submit" loading={create.isPending}>
              Create rule
            </Button>
          </Group>
        </Stack>
      </form>
    </Card>
  )
}
