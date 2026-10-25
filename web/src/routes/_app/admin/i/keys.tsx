import { Button, Card, Code, Group, Modal, NumberInput, Select, Stack, Table, Text, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { IconRotateClockwise } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { adminQuery, useAdminMutation } from '@/api/admin'
import { healthQuery, installKeys, signingKeysQuery } from '@/api/admin/install'
import { api, unwrap } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { KeyringCard } from '@/components/admin/install/KeyringCard'
import { StatusBadge, toneOf } from '@/components/admin/install/StatusBadge'
import { DateTime, Loading, Notice } from '@/components/admin/install/ui'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/i/keys')({
  component: Keys,
})

function Keys() {
  const keys = useQuery(signingKeysQuery)
  const health = useQuery(healthQuery)
  const caps = useQuery(adminQuery)
  const isOwner = !!caps.data?.operator_roles.includes('owner')
  const [opened, { open, close }] = useDisclosure(false)
  return (
    <Stack>
      <PageHeader
        title="Keys"
        description="Signing keys for OpenID Connect tokens and the master keys that protect stored secrets. Private key material is never shown."
        actions={
          isOwner ? (
            <Button leftSection={<IconRotateClockwise size={16} aria-hidden />} onClick={open}>
              Rotate signing key
            </Button>
          ) : null
        }
      />
      <Card>
        <Title order={2} size="h4" mb="xs">
          OIDC signing keys
        </Title>
        <Text size="sm" c="dimmed" mb="sm">
          Applications verify ID and access tokens with the public keys published at the JWKS endpoint. After a rotation
          the previous key keeps being published until its retirement time so existing tokens stay valid.
        </Text>
        <ErrorAlert error={keys.error} title="Could not load signing keys" />
        {keys.isPending ? <Loading label="Loading signing keys…" /> : null}
        {keys.data?.length === 0 ? <EmptyState>No signing keys yet; one is created on first use.</EmptyState> : null}
        {keys.data?.length ? (
          <ListTable minWidth={640} striped aria-label="OIDC signing keys" verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Key ID</Table.Th>
                <Table.Th>Algorithm</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th>Created</Table.Th>
                <Table.Th>Retires after</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {keys.data.map((k) => (
                <Table.Tr key={k.kid}>
                  <Table.Td>
                    <Code>{k.kid}</Code>
                  </Table.Td>
                  <Table.Td>{k.alg}</Table.Td>
                  <Table.Td>
                    <StatusBadge tone={k.state === 'retired' ? 'neutral' : toneOf(k.state)}>{k.state}</StatusBadge>
                  </Table.Td>
                  <Table.Td>
                    <DateTime value={k.created_at} />
                  </Table.Td>
                  <Table.Td>
                    <DateTime value={k.retire_after} />
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ListTable>
        ) : null}
      </Card>
      <ErrorAlert error={health.error} title="Could not load the keyring status" />
      {health.data ? <KeyringCard h={health.data} /> : null}
      {health.isPending ? <Loading label="Loading keyring status…" /> : null}
      <Modal
        closeButtonProps={{ 'aria-label': 'Close' }}
        lockScroll={false}
        opened={opened}
        onClose={close}
        title="Rotate signing key"
        centered
      >
        {opened ? <RotateForm onDone={close} /> : null}
      </Modal>
    </Stack>
  )
}

function RotateForm({ onDone }: { onDone: () => void }) {
  const form = useForm<{ alg: 'ES256' | 'RS256'; hours: number | string }>({
    initialValues: { alg: 'ES256', hours: 24 },
    validate: {
      hours: (v) => {
        const n = Number(v)
        return Number.isFinite(n) && n >= 0 && n <= 720 ? null : 'Enter 0 to 720 hours'
      },
    },
  })
  const rotate = useAdminMutation({
    mutationFn: async (v: { alg: 'ES256' | 'RS256'; hours: number | string }) =>
      unwrap(
        await api.POST('/installation/signing-keys/rotate', {
          body: { alg: v.alg, overlap_seconds: Math.round(Number(v.hours) * 3600) || undefined },
        }),
      ),
    success: (k) => `New ${k.alg} signing key ${k.kid} is active`,
    invalidate: [installKeys.keys],
    onSuccess: onDone,
  })
  return (
    <form
      onSubmit={form.onSubmit((v) => {
        rotate.mutate(v)
      })}
    >
      <Stack>
        <Notice tone="info">Only the installation owner can rotate keys, and it needs a recent sign-in.</Notice>
        <Select
          label="Algorithm"
          data={[
            { value: 'ES256', label: 'ES256 (ECDSA P-256)' },
            { value: 'RS256', label: 'RS256 (RSA)' },
          ]}
          allowDeselect={false}
          data-autofocus
          {...form.getInputProps('alg')}
        />
        <NumberInput
          label="Keep the old key published for (hours)"
          description="Tokens signed with the old key stay verifiable this long. 0 uses the default of 24 hours."
          min={0}
          max={720}
          {...form.getInputProps('hours')}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onDone}>
            Cancel
          </Button>
          <Button type="submit" loading={rotate.isPending}>
            Rotate key
          </Button>
        </Group>
      </Stack>
    </form>
  )
}
