import { Anchor, Button, Card, Group, SimpleGrid, Stack, Table, Text, Title } from '@mantine/core'
import { IconShieldCheck } from '@tabler/icons-react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { createFileRoute, Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { healthQuery, type SystemHealth } from '@/api/admin/install'
import { api, unwrap } from '@/api/client'
import { ErrorAlert, PageHeader } from '@/components/admin/kit'
import { formatBytes, formatDuration } from '@/components/admin/install/format'
import { StatusBadge, toneOf, type Tone } from '@/components/admin/install/StatusBadge'
import { DateTime, Loading, Notice, RefreshButton } from '@/components/admin/install/ui'
import { KeyringCard } from '@/components/admin/install/KeyringCard'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/i/health')({
  component: Health,
})

const REFRESH_MS = 30_000

function overall(h: SystemHealth): { tone: Tone; label: string } {
  if (h.checks.some((c) => c.status === 'critical')) return { tone: 'critical', label: 'Critical: action required' }
  if (h.checks.some((c) => c.status === 'warning')) return { tone: 'warning', label: 'Needs attention' }
  return { tone: 'ok', label: 'All checks passing' }
}

function Health() {
  const q = useQuery({ ...healthQuery, refetchInterval: REFRESH_MS })
  const verify = useMutation({
    mutationFn: async () => unwrap(await api.GET('/installation/audit/verify')),
  })
  const h = q.data
  return (
    <Stack>
      <PageHeader
        title="System health"
        description="Live status of this Porch installation. Refreshes automatically every 30 seconds."
        actions={
          <>
            <RefreshButton onClick={() => q.refetch()} loading={q.isFetching} />
            <Button
              variant="light"
              leftSection={<IconShieldCheck size={16} aria-hidden />}
              loading={verify.isPending}
              onClick={() => {
                verify.mutate()
              }}
            >
              Verify audit chain
            </Button>
          </>
        }
      />
      <VerifyResult verify={verify} />
      <ErrorAlert error={q.error} title="Could not load system health" />
      {q.isPending ? <Loading label="Loading system health…" /> : null}
      {h ? <HealthBody h={h} updatedAt={q.dataUpdatedAt} /> : null}
    </Stack>
  )
}

function VerifyResult({
  verify,
}: {
  verify: { data?: { ok: boolean; events: number; broken_at?: number; problem?: string }; error: unknown }
}) {
  if (verify.error) return <ErrorAlert error={verify.error} title="Could not verify the audit chain" />
  const r = verify.data
  if (!r) return null
  if (r.ok)
    return (
      <Notice tone="ok" title="Audit chain OK" live="status">
        All {r.events.toLocaleString()} audit events verified: the hash chain is intact.
      </Notice>
    )
  return (
    <Notice tone="critical" title="Audit chain broken" live="alert">
      Verification failed{r.broken_at ? ` at event #${String(r.broken_at)}` : ''} after checking{' '}
      {r.events.toLocaleString()} events{r.problem ? `: ${r.problem}` : '.'} Treat the audit log as possibly tampered
      with and investigate.
    </Notice>
  )
}

function Stat({ label, value, extra }: { label: string; value: ReactNode; extra?: ReactNode }) {
  return (
    <Card padding="md">
      <Text size="sm" c="dimmed">
        {label}
      </Text>
      <Text size="xl" fw={700}>
        {value}
      </Text>
      {extra}
    </Card>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Table.Tr>
      <Table.Th scope="row" fw={500} w="45%">
        {label}
      </Table.Th>
      <Table.Td>{children}</Table.Td>
    </Table.Tr>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <Title order={2} size="h4" mb="sm">
        {title}
      </Title>
      <Table aria-label={title} verticalSpacing={6}>
        <Table.Tbody>{children}</Table.Tbody>
      </Table>
    </Card>
  )
}

function HealthBody({ h, updatedAt }: { h: SystemHealth; updatedAt: number }) {
  const o = overall(h)
  const uptime = updatedAt - new Date(h.started_at).getTime()
  return (
    <Stack>
      <Card>
        <Group justify="space-between" wrap="wrap">
          <Group gap="sm">
            <Title order={2} size="h4">
              Overall status
            </Title>
            <StatusBadge tone={o.tone} size="lg">
              {o.label}
            </StatusBadge>
          </Group>
          <Text size="sm" c="dimmed">
            Last updated <DateTime value={new Date(updatedAt).toISOString()} />
          </Text>
        </Group>
        <ListTable minWidth={480} mt="md" aria-label="Health checks" verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Check</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Detail</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {h.checks.map((c) => (
              <Table.Tr key={c.name}>
                <Table.Td tt="capitalize">{c.name}</Table.Td>
                <Table.Td>
                  <StatusBadge tone={toneOf(c.status)}>{c.status}</StatusBadge>
                </Table.Td>
                <Table.Td>{c.detail ?? '—'}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ListTable>
      </Card>

      <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }}>
        <Stat label="Tenants" value={h.tenants.toLocaleString()} />
        <Stat label="Users" value={h.users.toLocaleString()} />
        <Stat label="Active sessions" value={h.active_sessions.toLocaleString()} />
        <Stat label="Audit events" value={h.audit_events.toLocaleString()} />
        <Stat
          label="Open alerts"
          value={h.open_alerts.toLocaleString()}
          extra={
            h.open_alerts > 0 ? (
              <Anchor component={Link} to="/admin/i/alerts" size="sm">
                Review alerts
              </Anchor>
            ) : null
          }
        />
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Section title="Server">
          <Row label="Version">{h.version}</Row>
          <Row label="Started">
            <DateTime value={h.started_at} />
          </Row>
          <Row label="Uptime">{formatDuration(uptime)}</Row>
          <Row label="Readiness">
            <Group gap="xs">
              <StatusBadge tone={h.ready ? 'ok' : 'critical'}>{h.ready ? 'ready' : 'not ready'}</StatusBadge>
              {h.ready_error ? <Text size="sm">{h.ready_error}</Text> : null}
            </Group>
          </Row>
        </Section>
        <Section title="Storage">
          <Row label="State">
            <Group gap="xs">
              <StatusBadge tone={toneOf(h.storage.state)}>{h.storage.state}</StatusBadge>
              {h.storage.reason ? <Text size="sm">{h.storage.reason}</Text> : null}
            </Group>
          </Row>
          <Row label="In this state since">
            <DateTime value={h.storage.since} />
          </Row>
          <Row label="Database size">{formatBytes(h.db_bytes)}</Row>
          <Row label="Write-ahead log size">{formatBytes(h.wal_bytes)}</Row>
        </Section>
        <Section title="Event outbox">
          <Row label="Pending">{h.outbox_pending.toLocaleString()}</Row>
          <Row label="Dead-lettered">
            {h.outbox_dead > 0 ? (
              <StatusBadge tone="warning">{h.outbox_dead.toLocaleString()}</StatusBadge>
            ) : (
              h.outbox_dead.toLocaleString()
            )}
          </Row>
          <Row label="Oldest pending event">
            <DateTime value={h.outbox_oldest_pending_at} />
          </Row>
        </Section>
        <Section title="Backups">
          <Row label="Configured">
            <StatusBadge tone={h.backups.configured ? 'ok' : 'warning'}>
              {h.backups.configured ? 'yes' : 'not configured'}
            </StatusBadge>
          </Row>
          <Row label="Last backup">
            <DateTime value={h.backups.last_at} />
          </Row>
          <Row label="Last backup result">
            {h.backups.last_at ? (
              <StatusBadge tone={h.backups.last_ok ? 'ok' : 'critical'}>
                {h.backups.last_ok ? 'succeeded' : 'failed'}
              </StatusBadge>
            ) : (
              '—'
            )}
          </Row>
        </Section>
      </SimpleGrid>

      <KeyringCard h={h} />
    </Stack>
  )
}
