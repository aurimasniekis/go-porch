import {
  Alert,
  Badge,
  Button,
  Group,
  Modal,
  MultiSelect,
  NumberInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
} from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { IconAlertTriangle, IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useAdminMutation } from '@/api/admin'
import { api, check, unwrap, type Schemas } from '@/api/client'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { CopyField } from '@/components/admin/tenant/common'
import { ListTable } from '@/components/ListTable'

type Token = Schemas['Token']

/** Where tokens live: the installation, or one tenant (slug) with the permissions the caller may delegate. */
export type TokenScope = { kind: 'installation' } | { kind: 'tenant'; tenant: string; permissions: string[] }

function tokensKey(scope: TokenScope) {
  return scope.kind === 'installation' ? ['automation-tokens', 'installation'] : ['automation-tokens', scope.tenant]
}

function fmt(v: string | undefined | null) {
  return v ? new Date(v).toLocaleString() : '—'
}

function status(t: Token, now: number) {
  if (t.revoked_at) return 'revoked'
  if (!t.never_expires && t.expires_at && new Date(t.expires_at).getTime() <= now) return 'expired'
  return 'active'
}

function CreateToken({ scope, onCreated }: { scope: TokenScope; onCreated: (t: Schemas['CreatedToken']) => void }) {
  const [opened, { open, close }] = useDisclosure(false)
  const form = useForm({
    initialValues: { name: '', role: 'admin', permissions: [] as string[], days: 90, never: false },
    validate: {
      name: (v) => (v.trim() ? null : 'Name is required'),
      permissions: (v) => (scope.kind === 'tenant' && v.length === 0 ? 'Choose at least one permission' : null),
      days: (v, values) => (values.never || (v >= 1 && v <= 366) ? null : 'Between 1 and 366 days'),
    },
  })
  const create = useAdminMutation({
    mutationFn: async (v: typeof form.values) => {
      if (scope.kind === 'installation') {
        return unwrap(
          await api.POST('/installation/automation-tokens', {
            body: v.never
              ? { name: v.name.trim(), role: v.role as 'admin' | 'auditor', never_expires: true }
              : { name: v.name.trim(), role: v.role as 'admin' | 'auditor', expires_in_days: v.days },
          }),
        )
      }
      return unwrap(
        await api.POST('/tenants/{tenant}/automation-tokens', {
          params: { path: { tenant: scope.tenant } },
          body: { name: v.name.trim(), permissions: v.permissions, expires_in_days: v.days },
        }),
      )
    },
    invalidate: [tokensKey(scope)],
    onSuccess: (t) => {
      close()
      form.reset()
      onCreated(t)
    },
  })
  return (
    <>
      <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={open}>
        New token
      </Button>
      <Modal opened={opened} onClose={close} title="New automation token" centered>
        <form
          onSubmit={form.onSubmit((v) => {
            create.mutate(v)
          })}
        >
          <Stack>
            <TextInput
              label="Name"
              description="What uses it, e.g. terraform"
              required
              {...form.getInputProps('name')}
            />
            {scope.kind === 'installation' ? (
              <Select
                label="Role"
                description="admin manages every tenant and installation setting; auditor only reads."
                data={[
                  { value: 'admin', label: 'Admin' },
                  { value: 'auditor', label: 'Auditor' },
                ]}
                allowDeselect={false}
                {...form.getInputProps('role')}
              />
            ) : (
              <MultiSelect
                label="Permissions"
                description="Only permissions you hold yourself. The token also stops working for anything you lose later."
                data={scope.permissions}
                searchable
                {...form.getInputProps('permissions')}
              />
            )}
            {scope.kind === 'installation' ? (
              <Switch
                label="Never expires"
                description="For your own Terraform or break-glass automation: keeps working without an expiry and while the identity provider (Google) is unavailable. Only installation owners can issue it."
                {...form.getInputProps('never', { type: 'checkbox' })}
              />
            ) : null}
            {form.values.never ? (
              <Alert color="orange" icon={<IconAlertTriangle size={18} />} title="A token that never expires">
                Anyone who obtains it can manage the installation until you revoke it. Store it like a root password,
                and revoke it here as soon as it is no longer needed.
              </Alert>
            ) : (
              <NumberInput label="Expires in (days)" min={1} max={366} required {...form.getInputProps('days')} />
            )}
            <Text size="xs" c="dimmed">
              Creating a token needs a recent sign-in. Tokens cannot create other tokens, change installation roles or
              rotate signing keys.
            </Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" loading={create.isPending}>
                Create token
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </>
  )
}

/** Lists, creates and revokes automation tokens (ADR-0041). */
export function AutomationTokens({ scope, canManage }: { scope: TokenScope; canManage: boolean }) {
  const q = useQuery({
    queryKey: tokensKey(scope),
    queryFn: async () =>
      scope.kind === 'installation'
        ? unwrap(await api.GET('/installation/automation-tokens'))
        : unwrap(await api.GET('/tenants/{tenant}/automation-tokens', { params: { path: { tenant: scope.tenant } } })),
  })
  const [secret, setSecret] = useState<Schemas['CreatedToken'] | null>(null)
  const revoke = useAdminMutation({
    mutationFn: async (id: string) => {
      check(
        scope.kind === 'installation'
          ? await api.DELETE('/installation/automation-tokens/{token}', { params: { path: { token: id } } })
          : await api.DELETE('/tenants/{tenant}/automation-tokens/{token}', {
              params: { path: { tenant: scope.tenant, token: id } },
            }),
      )
    },
    success: 'Token revoked',
    invalidate: [tokensKey(scope)],
  })
  const [now] = useState(() => Date.now())
  return (
    <Stack>
      <PageHeader
        title="Automation tokens"
        description={
          scope.kind === 'installation'
            ? 'Bearer tokens for Terraform and scripts that manage the whole installation. Send them as Authorization: Bearer porch_at_…'
            : 'Bearer tokens limited to this tenant and a set of permissions. They act for the person who created them.'
        }
        actions={canManage ? <CreateToken scope={scope} onCreated={setSecret} /> : null}
      />
      <ErrorAlert error={q.error} title="Could not load tokens" />
      {q.data?.length === 0 ? <EmptyState>No automation tokens.</EmptyState> : null}
      {q.data?.length ? (
        <ListTable minWidth={820} striped aria-label="Automation tokens" verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Grants</Table.Th>
              <Table.Th>Created by</Table.Th>
              <Table.Th>Expires</Table.Th>
              <Table.Th>Last used</Table.Th>
              <Table.Th>Status</Table.Th>
              {canManage ? <Table.Th>Actions</Table.Th> : null}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data.map((t) => {
              const st = status(t, now)
              return (
                <Table.Tr key={t.id}>
                  <Table.Td>
                    <Text size="sm" fw={500}>
                      {t.name}
                    </Text>
                    <Text size="xs" c="dimmed">
                      …{t.hint}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{t.role ? `installation ${t.role}` : t.permissions.join(', ')}</Text>
                  </Table.Td>
                  <Table.Td>{t.creator_name ?? t.created_by}</Table.Td>
                  <Table.Td>
                    {t.never_expires ? (
                      <Badge variant="light" color="orange">
                        never
                      </Badge>
                    ) : (
                      fmt(t.expires_at)
                    )}
                  </Table.Td>
                  <Table.Td>
                    {fmt(t.last_used_at)}
                    {t.last_used_ip ? (
                      <Text size="xs" c="dimmed">
                        {t.last_used_ip}
                      </Text>
                    ) : null}
                  </Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={st === 'active' ? 'green' : 'gray'}>
                      {st}
                    </Badge>
                  </Table.Td>
                  {canManage ? (
                    <Table.Td>
                      {st === 'active' ? (
                        <ConfirmButton
                          label="Revoke"
                          title={`Revoke ${t.name}?`}
                          loading={revoke.isPending}
                          onConfirm={() => revoke.mutateAsync(t.id)}
                        >
                          Requests using this token fail immediately.
                        </ConfirmButton>
                      ) : null}
                    </Table.Td>
                  ) : null}
                </Table.Tr>
              )
            })}
          </Table.Tbody>
        </ListTable>
      ) : null}
      <Modal
        opened={secret !== null}
        onClose={() => {
          setSecret(null)
        }}
        title="Token created"
        size="lg"
        centered
        closeOnClickOutside={false}
      >
        {secret ? (
          <Stack>
            <Alert color="yellow" icon={<IconAlertTriangle size={18} />} title="Shown only once">
              Copy the token now. Porch keeps only a hash and cannot show it again.
            </Alert>
            <CopyField label="Token" value={secret.token} secret />
            <Group justify="flex-end">
              <Button
                onClick={() => {
                  setSecret(null)
                }}
              >
                I have stored the token
              </Button>
            </Group>
          </Stack>
        ) : null}
      </Modal>
    </Stack>
  )
}
