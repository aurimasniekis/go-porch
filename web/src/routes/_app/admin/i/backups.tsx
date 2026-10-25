import { Alert, Badge, Button, Card, Code, Group, Stack, Table, Text } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { adminQuery, useAdminMutation } from '@/api/admin'
import { api, unwrap } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { CopyField } from '@/components/admin/tenant/common'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/i/backups')({
  component: Backups,
})

const backupsKey = ['install', 'backups']

function bytes(n: number) {
  if (n < 1024) return `${String(n)} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / 1024 / 1024).toFixed(1)} MiB`
}

function Backups() {
  const caps = useQuery(adminQuery)
  const q = useQuery({ queryKey: backupsKey, queryFn: async () => unwrap(await api.GET('/installation/backups')) })
  const run = useAdminMutation({
    mutationFn: async () => unwrap(await api.POST('/installation/backups')),
    success: 'Backup complete',
    invalidate: [backupsKey, ['install', 'health']],
  })
  const canRun = caps.data?.installation ?? false
  const st = q.data
  return (
    <Stack>
      <PageHeader
        title="Backups"
        description="Encrypted with age to offline recipients and stored in S3-compatible storage. Porch can write backups but cannot read them."
        actions={
          canRun && st?.enabled ? (
            <Button
              loading={run.isPending}
              onClick={() => {
                run.mutate()
              }}
            >
              Back up now
            </Button>
          ) : null
        }
      />
      <ErrorAlert error={q.error} title="Could not load backups" />
      {st && !st.enabled ? (
        <Alert color="yellow" title="Backups are not configured">
          Set <Code>backup.enabled</Code>, <Code>backup.recipients</Code> and <Code>backup.s3</Code> in the
          configuration. Generate an offline identity with <Code>porch backup keygen</Code>.
        </Alert>
      ) : null}
      {st?.enabled ? (
        <Card>
          <Stack gap="sm">
            <Text size="sm">
              Every {Math.round(st.interval_seconds / 3600)} h. Restoring needs the offline age identity and this
              verification key (it proves a backup came from this installation):
            </Text>
            {st.verify_key ? <CopyField label="Verification key" value={st.verify_key} /> : null}
          </Stack>
        </Card>
      ) : null}
      {st?.runs.length === 0 ? <EmptyState>No backup has run yet.</EmptyState> : null}
      {st?.runs.length ? (
        <ListTable minWidth={720} striped aria-label="Backup runs" verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Started</Table.Th>
              <Table.Th>Trigger</Table.Th>
              <Table.Th>Result</Table.Th>
              <Table.Th>Database</Table.Th>
              <Table.Th>Stored</Table.Th>
              <Table.Th>KEK</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {st.runs.map((r) => (
              <Table.Tr key={r.id}>
                <Table.Td>
                  <Text size="sm">{new Date(r.started_at).toLocaleString()}</Text>
                  <Text size="xs" c="dimmed">
                    {r.id}
                  </Text>
                </Table.Td>
                <Table.Td>{r.trigger}</Table.Td>
                <Table.Td>
                  <Group gap={4}>
                    <Badge variant="light" color={r.ok === undefined ? 'gray' : r.ok ? 'green' : 'red'}>
                      {r.ok === undefined ? 'running' : r.ok ? 'ok' : 'failed'}
                    </Badge>
                    {r.error ? (
                      <Text size="xs" c="dimmed">
                        {r.error}
                      </Text>
                    ) : null}
                  </Group>
                </Table.Td>
                <Table.Td>{bytes(r.db_bytes)}</Table.Td>
                <Table.Td>{bytes(r.stored_bytes)}</Table.Td>
                <Table.Td>{r.kek_included ? 'included' : '—'}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ListTable>
      ) : null}
    </Stack>
  )
}
