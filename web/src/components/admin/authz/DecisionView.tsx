import { Alert, Card, Code, Group, SimpleGrid, Stack, Table, Text, Title } from '@mantine/core'
import { IconCircleCheck, IconCircleX } from '@tabler/icons-react'
import type { Decision } from '@/api/admin/authz'
import { alertTitleStyles, Perm, Tag, YesNo } from './common'
import { describeReason } from './logic'
import { ListTable } from '@/components/ListTable'

/** Renders an authorization decision and its explain trace (POST /tenants/{t}/authz/check). */
export function DecisionView({ decision }: { decision: Decision }) {
  const tr = decision.trace
  const ctx = tr.context
  return (
    <Stack gap="md" role="region" aria-label="Decision">
      <Alert
        color={decision.allowed ? 'green' : 'red'}
        icon={decision.allowed ? <IconCircleCheck size={20} /> : <IconCircleX size={20} />}
        title={decision.allowed ? 'Allowed' : 'Denied'}
        styles={alertTitleStyles}
      >
        <Group gap="xs">
          <Text size="sm">{describeReason(decision.reason)}</Text>
          <Code>{decision.reason}</Code>
        </Group>
      </Alert>
      <Group gap="xs">
        {tr.simulated ? <Tag color="orange">simulated context</Tag> : <Tag color="gray">live context</Tag>}
        <Text size="sm" c="dimmed">
          Model epoch {tr.epoch}
        </Text>
      </Group>

      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <Card padding="sm">
          <Title order={3} size="h5" mb={4}>
            Tenant gate
          </Title>
          <YesNo value={tr.tenant_gate.passed} yes="passed" no="not passed" />
          <Text size="sm" c="dimmed">
            via {tr.tenant_gate.via || 'none'}
          </Text>
        </Card>
        <Card padding="sm">
          <Title order={3} size="h5" mb={4}>
            Groups
          </Title>
          {tr.groups.length > 0 ? (
            <Group gap={4}>
              {tr.groups.map((g) => (
                <Tag key={g} color="teal">
                  {g}
                </Tag>
              ))}
            </Group>
          ) : (
            <Text size="sm" c="dimmed">
              No groups
            </Text>
          )}
        </Card>
      </SimpleGrid>

      <div>
        <Title order={3} size="h5" mb={4}>
          Candidate grants
        </Title>
        {tr.candidates.length === 0 ? (
          <Text size="sm" c="dimmed">
            No assignment grants this action for this resource.
          </Text>
        ) : (
          <ListTable
            minWidth={640}
            scroll={{ type: 'native', tabIndex: 0, role: 'region', 'aria-label': 'Candidate grants, scrollable' }}
            aria-label="Candidate grants"
            withTableBorder
          >
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Role</Table.Th>
                <Table.Th>Via</Table.Th>
                <Table.Th>Scope</Table.Th>
                <Table.Th>Permission</Table.Th>
                <Table.Th>Condition</Table.Th>
                <Table.Th>Applies</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {tr.candidates.map((c, i) => (
                <Table.Tr key={`${c.assignment_id ?? 'implicit'}-${c.permission}-${String(i)}`}>
                  <Table.Td>{c.role}</Table.Td>
                  <Table.Td>{c.via}</Table.Td>
                  <Table.Td>
                    <Text size="sm" style={{ overflowWrap: 'anywhere' }}>
                      {c.scope}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Perm>{c.permission}</Perm>
                  </Table.Td>
                  <Table.Td>
                    {c.condition ? (
                      <Stack gap={2}>
                        <Group gap={6} wrap="nowrap">
                          <Code>{c.condition.slug}</Code>
                          <YesNo value={c.condition.result} yes="true" no="false" />
                        </Group>
                        {c.condition.error ? (
                          <Text size="xs" c="red">
                            {c.condition.error}
                          </Text>
                        ) : null}
                      </Stack>
                    ) : (
                      <Text size="sm" c="dimmed">
                        none
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <YesNo value={c.applies} yes="✓ applies" no="✗ does not apply" />
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ListTable>
        )}
      </div>

      <div>
        <Title order={3} size="h5" mb={4}>
          Deny policies
        </Title>
        {tr.deny_policies.length === 0 ? (
          <Text size="sm" c="dimmed">
            No deny policy covers this action.
          </Text>
        ) : (
          <ListTable aria-label="Deny policies evaluated" withTableBorder>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Policy</Table.Th>
                <Table.Th>Result</Table.Th>
                <Table.Th>Error</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {tr.deny_policies.map((p) => (
                <Table.Tr key={p.policy_id}>
                  <Table.Td>
                    <Code>{p.slug}</Code>
                  </Table.Td>
                  <Table.Td>
                    <YesNo value={!p.result} yes="not matched" no="matched — denies" />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{p.error ?? '—'}</Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ListTable>
        )}
      </div>

      <div>
        <Title order={3} size="h5" mb={4}>
          Context {tr.simulated ? '(simulated)' : '(derived by the server)'}
        </Title>
        <Table aria-label="Evaluation context" withTableBorder>
          <Table.Tbody>
            {(
              [
                ['ip', ctx.ip],
                ['network', ctx.network],
                ['tenant', ctx.tenant],
                ['hour (UTC)', String(ctx.hour)],
                ['weekday (UTC)', ctx.weekday],
              ] as [string, string | undefined][]
            ).map(([k, v]) => (
              <Table.Tr key={k}>
                <Table.Th scope="row" w={160}>
                  {k}
                </Table.Th>
                <Table.Td>{v ? <Code>{v}</Code> : <Text size="sm">—</Text>}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </div>
    </Stack>
  )
}
