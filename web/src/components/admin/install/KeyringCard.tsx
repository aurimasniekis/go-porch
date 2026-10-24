import { Card, Table, Text, Title } from '@mantine/core'
import type { SystemHealth } from '@/api/admin/install'
import { StatusBadge } from './StatusBadge'

/** Keyring purposes with their active and available key versions (no key material is ever returned). */
export function KeyringCard({ h }: { h: SystemHealth }) {
  return (
    <Card>
      <Title order={2} size="h4" mb="xs">
        Keyring
      </Title>
      <Text size="sm" c="dimmed" mb="sm">
        Master keys loaded from the host, by purpose. Older versions stay available to decrypt existing data.
      </Text>
      {h.keyring.length === 0 ? (
        <Text c="dimmed">No keyring information available.</Text>
      ) : (
        <Table.ScrollContainer minWidth={420}>
          <Table aria-label="Keyring purposes" verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Purpose</Table.Th>
                <Table.Th>Active version</Table.Th>
                <Table.Th>Available versions</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {h.keyring.map((k) => (
                <Table.Tr key={k.purpose}>
                  <Table.Td>{k.purpose}</Table.Td>
                  <Table.Td>
                    {k.active_version > 0 ? (
                      `v${String(k.active_version)}`
                    ) : (
                      <StatusBadge tone="critical">none</StatusBadge>
                    )}
                  </Table.Td>
                  <Table.Td>
                    {k.versions.length
                      ? [...k.versions]
                          .sort((a, b) => a - b)
                          .map((v) => `v${String(v)}`)
                          .join(', ')
                      : '—'}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Card>
  )
}
