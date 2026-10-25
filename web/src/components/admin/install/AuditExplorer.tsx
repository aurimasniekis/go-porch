import { ActionIcon, Button, Card, Code, Group, SimpleGrid, Select, Stack, Table, Text, TextInput } from '@mantine/core'
import { IconChevronDown, IconChevronRight } from '@tabler/icons-react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { Fragment, useMemo, useState, type SyntheticEvent, type ReactNode } from 'react'
import {
  allTenantsQuery,
  auditPagesQuery,
  emptyAuditFilter,
  type AuditEvent,
  type AuditFilter,
} from '@/api/admin/install'
import { EmptyState, ErrorAlert } from '@/components/admin/kit'
import { actorLabel, detailsJson, localInputToIso, targetLabel } from './format'
import { StatusBadge, toneOf } from './StatusBadge'
import { DateTime, Loading, Notice, RefreshButton } from './ui'
import { ListTable } from '@/components/ListTable'

const actionRE = /^[a-z_.]{1,64}$/

/** Filters as typed into the form (since/until are datetime-local values). */
interface Draft {
  actor: string
  target: string
  action: string
  outcome: AuditFilter['outcome']
  since: string
  until: string
  tenant: string
}

export interface AuditExplorerProps {
  /** Tenant ID or slug: search that tenant's log (audit:read). Omit for the installation log. */
  tenant?: string
  /** Initial filter values (e.g. from the URL). */
  initial?: Partial<Pick<AuditFilter, 'actor' | 'target' | 'action' | 'tenant'>>
}

/** Searchable, paginated audit log (newest first) with expandable event details. */
export function AuditExplorer({ tenant, initial }: AuditExplorerProps) {
  const start: Draft = { ...emptyAuditFilter, ...initial }
  const [draft, setDraft] = useState<Draft>(start)
  const [applied, setApplied] = useState<AuditFilter>({ ...emptyAuditFilter, ...initial })
  const [actionError, setActionError] = useState('')
  const [open, setOpen] = useState<Set<string>>(new Set())
  const installation = !tenant
  const tenants = useQuery({ ...allTenantsQuery, enabled: installation })
  const tenantNames = useMemo(() => new Map((tenants.data ?? []).map((t) => [t.id, t.name])), [tenants.data])
  const q = useInfiniteQuery(auditPagesQuery({ tenant }, applied))
  const events = q.data?.pages.flatMap((p) => p.items) ?? []

  const set = (k: keyof Draft) => (v: string) => {
    setDraft((d) => ({ ...d, [k]: v }))
  }
  const apply = (e: SyntheticEvent) => {
    e.preventDefault()
    const action = draft.action.trim()
    if (action && !actionRE.test(action)) {
      setActionError('Use lowercase letters, dots or underscores (for example tenant. or oidc.token_issued)')
      return
    }
    setActionError('')
    setOpen(new Set())
    setApplied({
      actor: draft.actor.trim(),
      target: draft.target.trim(),
      action,
      outcome: draft.outcome,
      since: localInputToIso(draft.since),
      until: localInputToIso(draft.until),
      tenant: draft.tenant,
    })
  }
  const reset = () => {
    setDraft({ ...emptyAuditFilter })
    setApplied({ ...emptyAuditFilter })
    setActionError('')
    setOpen(new Set())
  }
  const toggle = (id: string) => {
    setOpen((s) => {
      const n = new Set(s)
      if (n.has(id)) n.delete(id)
      else n.add(id)
      return n
    })
  }
  const columns = 7

  return (
    <Stack>
      <Card component="form" onSubmit={apply} aria-label="Audit filters" padding="md">
        <SimpleGrid cols={{ base: 1, sm: 2, lg: installation ? 4 : 3 }} spacing="sm">
          <TextInput
            label="Action prefix"
            placeholder="tenant."
            description="e.g. tenant. or oidc.token_issued"
            value={draft.action}
            error={actionError || undefined}
            onChange={(e) => {
              set('action')(e.currentTarget.value)
            }}
          />
          <TextInput
            label="Actor ID"
            description="User or client ID"
            value={draft.actor}
            onChange={(e) => {
              set('actor')(e.currentTarget.value)
            }}
          />
          <TextInput
            label="Target ID"
            description="ID of the affected object"
            value={draft.target}
            onChange={(e) => {
              set('target')(e.currentTarget.value)
            }}
          />
          <Select
            label="Outcome"
            description="Result of the action"
            data={[
              { value: '', label: 'Any outcome' },
              { value: 'success', label: 'Success' },
              { value: 'failure', label: 'Failure' },
              { value: 'denied', label: 'Denied' },
            ]}
            value={draft.outcome}
            allowDeselect={false}
            onChange={(v) => {
              set('outcome')(v ?? '')
            }}
          />
          <TextInput
            type="datetime-local"
            label="From"
            description="Your local time"
            value={draft.since}
            onChange={(e) => {
              set('since')(e.currentTarget.value)
            }}
          />
          <TextInput
            type="datetime-local"
            label="Until"
            description="Your local time"
            value={draft.until}
            onChange={(e) => {
              set('until')(e.currentTarget.value)
            }}
          />
          {installation ? (
            <Select
              label="Tenant"
              description="Only events of this tenant"
              placeholder="All tenants"
              searchable
              clearable
              data={(tenants.data ?? []).map((t) => ({ value: t.id, label: `${t.name} (${t.slug})` }))}
              value={draft.tenant || null}
              onChange={(v) => {
                set('tenant')(v ?? '')
              }}
            />
          ) : null}
        </SimpleGrid>
        <Group mt="md" gap="xs">
          <Button type="submit" loading={q.isFetching && !q.isFetchingNextPage}>
            Apply filters
          </Button>
          <Button variant="default" onClick={reset}>
            Reset
          </Button>
          <RefreshButton onClick={() => q.refetch()} loading={q.isRefetching && !q.isFetchingNextPage} />
        </Group>
      </Card>

      <ErrorAlert error={q.error} title="Could not load the audit log" />
      {q.isPending ? <Loading label="Loading audit events…" /> : null}
      {q.isSuccess && events.length === 0 ? <EmptyState>No audit events match these filters.</EmptyState> : null}
      {events.length > 0 ? (
        <ListTable minWidth={860} striped highlightOnHover aria-label="Audit events, newest first" verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={40}>
                <span className="visually-hidden">Details</span>
              </Table.Th>
              <Table.Th>Time</Table.Th>
              <Table.Th>Actor</Table.Th>
              <Table.Th>Action</Table.Th>
              <Table.Th>Target</Table.Th>
              <Table.Th>Outcome</Table.Th>
              <Table.Th>Source IP</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {events.map((ev) => {
              const expanded = open.has(ev.id)
              const detailsId = `audit-details-${ev.id}`
              return (
                <Fragment key={ev.id}>
                  <Table.Tr>
                    <Table.Td className="porch-list-corner">
                      <ActionIcon
                        variant="subtle"
                        color="gray"
                        aria-label={`${expanded ? 'Hide' : 'Show'} details of ${ev.action} event ${String(ev.seq)}`}
                        aria-expanded={expanded}
                        aria-controls={expanded ? detailsId : undefined}
                        onClick={() => {
                          toggle(ev.id)
                        }}
                      >
                        {expanded ? (
                          <IconChevronDown size={16} aria-hidden />
                        ) : (
                          <IconChevronRight size={16} aria-hidden />
                        )}
                      </ActionIcon>
                    </Table.Td>
                    <Table.Td style={{ whiteSpace: 'nowrap' }}>
                      <DateTime value={ev.at} />
                    </Table.Td>
                    <Table.Td>{actorLabel(ev)}</Table.Td>
                    <Table.Td>
                      <Code>{ev.action}</Code>
                    </Table.Td>
                    <Table.Td style={{ wordBreak: 'break-all' }}>{targetLabel(ev)}</Table.Td>
                    <Table.Td>
                      <StatusBadge tone={toneOf(ev.outcome)} size="sm">
                        {ev.outcome}
                      </StatusBadge>
                    </Table.Td>
                    <Table.Td>{ev.source_ip ?? '—'}</Table.Td>
                  </Table.Tr>
                  {expanded ? (
                    <Table.Tr id={detailsId}>
                      <Table.Td colSpan={columns}>
                        <EventDetails ev={ev} tenantName={ev.tenant_id ? tenantNames.get(ev.tenant_id) : undefined} />
                      </Table.Td>
                    </Table.Tr>
                  ) : null}
                </Fragment>
              )
            })}
          </Table.Tbody>
        </ListTable>
      ) : null}
      {events.length > 0 ? (
        <Group justify="space-between">
          <Text size="sm" c="dimmed" aria-live="polite">
            Showing {events.length} {events.length === 1 ? 'event' : 'events'}
            {q.hasNextPage ? '' : ' (end of log)'}
          </Text>
          {q.hasNextPage ? (
            <Button variant="default" loading={q.isFetchingNextPage} onClick={() => void q.fetchNextPage()}>
              Load more
            </Button>
          ) : null}
        </Group>
      ) : null}
    </Stack>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <Text size="xs" c="dimmed" fw={600}>
        {label}
      </Text>
      <Text size="sm" style={{ wordBreak: 'break-all' }}>
        {children}
      </Text>
    </div>
  )
}

function EventDetails({ ev, tenantName }: { ev: AuditEvent; tenantName?: string }) {
  return (
    <Stack gap="sm" py="xs">
      <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="sm">
        <Field label="Event ID">{ev.id}</Field>
        <Field label="Sequence">{ev.seq}</Field>
        <Field label="Request ID">{ev.request_id ?? '—'}</Field>
        <Field label="Chain hash (prefix)">
          <Code>{ev.chain_hash_prefix || '—'}</Code>
        </Field>
        <Field label="Actor">{ev.actor_id ? `${ev.actor_type}:${ev.actor_id}` : ev.actor_type}</Field>
        <Field label="Tenant">
          {ev.tenant_id ? (tenantName ? `${tenantName} (${ev.tenant_id})` : ev.tenant_id) : '—'}
        </Field>
        <Field label="Sign-in method">{ev.auth_method ?? '—'}</Field>
        <Field label="Reason code">{ev.reason_code ?? '—'}</Field>
      </SimpleGrid>
      {ev.sealed_details ? (
        <Notice tone="neutral" title="Sealed details">
          <Text size="sm">
            This event also has sensitive details that are encrypted at rest and are not shown here. They can only be
            read with host access.
          </Text>
        </Notice>
      ) : null}
      <div>
        <Text size="xs" c="dimmed" fw={600} mb={4}>
          Details
        </Text>
        <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
          {detailsJson(ev.details)}
        </Code>
      </div>
    </Stack>
  )
}
