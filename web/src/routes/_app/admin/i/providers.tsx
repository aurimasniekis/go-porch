import {
  Button,
  Code,
  Group,
  Modal,
  PasswordInput,
  Select,
  Stack,
  Switch,
  Table,
  TagsInput,
  Text,
  TextInput,
  VisuallyHidden,
} from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, ifMatch, useAdminMutation } from '@/api/admin'
import { installKeys, loginSettingsQuery, providersQuery, type IdentityProvider } from '@/api/admin/install'
import { api, ApiError, check, unwrap, type Schemas } from '@/api/client'
import { EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'
import { useVersionedMutation } from '@/components/admin/install/hooks'
import { ManagedBy } from '@/components/admin/install/ManagedBy'
import { StatusBadge } from '@/components/admin/install/StatusBadge'
import { ConfirmAction } from '@/components/admin/install/ConfirmAction'
import { Loading, Notice } from '@/components/admin/install/ui'
import { ListTable } from '@/components/ListTable'

export const Route = createFileRoute('/_app/admin/i/providers')({
  component: Providers,
})

const domainRE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/

function Providers() {
  const q = useQuery(providersQuery)
  const caps = useQuery(adminQuery)
  const canWrite = !!caps.data?.installation
  const [createOpened, createDisclosure] = useDisclosure(false)
  const [editing, setEditing] = useState<IdentityProvider | null>(null)
  return (
    <Stack>
      <PageHeader
        title="Identity providers"
        description="Upstream sign-in providers (Google or any OpenID Connect provider). Users sign in with these; Porch never links accounts by email."
        actions={
          canWrite ? (
            <Button leftSection={<IconPlus size={16} aria-hidden />} onClick={createDisclosure.open}>
              New provider
            </Button>
          ) : null
        }
      />
      <Notice tone="info">
        Adding, changing or deleting a provider needs a recent sign-in. If yours is older than a few minutes you are
        asked to confirm it&apos;s you and then brought back here. Client secrets are write-only and never shown again.
      </Notice>
      <ErrorAlert error={q.error} title="Could not load identity providers" />
      {q.isPending ? <Loading label="Loading identity providers…" /> : null}
      {q.data?.length === 0 ? <EmptyState>No identity providers yet.</EmptyState> : null}
      {q.data?.length ? (
        <ListTable minWidth={1000} striped highlightOnHover aria-label="Identity providers" verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Kind</Table.Th>
              <Table.Th>Issuer and client</Table.Th>
              <Table.Th>Allowed domains</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Managed by</Table.Th>
              {canWrite ? (
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              ) : null}
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data.map((p) => (
              <ProviderRow
                key={p.id}
                p={p}
                canWrite={canWrite}
                onEdit={() => {
                  setEditing(p)
                }}
              />
            ))}
          </Table.Tbody>
        </ListTable>
      ) : null}
      {q.data?.some((p) => p.enabled) ? (
        <SignInPageSettings providers={q.data.filter((p) => p.enabled)} canWrite={canWrite} />
      ) : null}
      <Modal
        closeButtonProps={{ 'aria-label': 'Close' }}
        lockScroll={false}
        opened={createOpened}
        onClose={createDisclosure.close}
        title="New identity provider"
        centered
        size="lg"
      >
        {createOpened ? <ProviderForm onDone={createDisclosure.close} /> : null}
      </Modal>
      <Modal
        closeButtonProps={{ 'aria-label': 'Close' }}
        lockScroll={false}
        opened={!!editing}
        onClose={() => {
          setEditing(null)
        }}
        title={editing ? `Edit ${editing.name}` : 'Edit provider'}
        centered
        size="lg"
      >
        {editing ? (
          <ProviderForm
            key={`${editing.id}:${String(editing.version)}`}
            provider={editing}
            onDone={() => {
              setEditing(null)
            }}
          />
        ) : null}
      </Modal>
    </Stack>
  )
}

/** Whether the sign-in page goes straight to one provider; /login?all=1 always shows every method. */
function SignInPageSettings({ providers, canWrite }: { providers: IdentityProvider[]; canWrite: boolean }) {
  const s = useQuery(loginSettingsQuery)
  const save = useAdminMutation({
    mutationFn: async (slug: string) =>
      unwrap(await api.PUT('/installation/login', { body: { direct_provider: slug } })),
    success: 'Sign-in page saved',
    invalidate: [loginSettingsQuery.queryKey],
  })
  const current = s.data?.direct_provider ?? ''
  return (
    <Stack gap="xs" maw={560}>
      <Select
        label="Sign-in page"
        description="Send people straight to one provider instead of showing every sign-in method. The full page, with the backup login, stays at /login?all=1 and appears after a failed sign-in or signing out."
        data={[
          { value: '', label: 'Show every sign-in method' },
          ...providers.map((p) => ({ value: p.slug, label: `Go straight to ${p.name}` })),
        ]}
        value={current}
        allowDeselect={false}
        disabled={!canWrite || s.isPending || save.isPending}
        onChange={(v) => {
          if (v !== null && v !== current) save.mutate(v)
        }}
      />
      {current ? (
        <Text size="xs" c="dimmed">
          Full sign-in page: <Code>{`${window.location.origin}/login?all=1`}</Code>
        </Text>
      ) : null}
    </Stack>
  )
}

function ProviderRow({ p, canWrite, onEdit }: { p: IdentityProvider; canWrite: boolean; onEdit: () => void }) {
  const del = useVersionedMutation({
    mutationFn: async () => {
      check(
        await api.DELETE('/identity-providers/{provider}', {
          params: { path: { provider: p.id }, header: ifMatch(p.version) },
        }),
      )
    },
    success: `${p.name} deleted`,
    invalidate: [installKeys.providers],
  })
  return (
    <Table.Tr>
      <Table.Td>
        <Text size="sm" fw={500}>
          {p.name}
        </Text>
        <Code>{p.slug}</Code>
      </Table.Td>
      <Table.Td>{p.kind === 'google' ? 'Google' : 'OpenID Connect'}</Table.Td>
      <Table.Td style={{ wordBreak: 'break-all' }}>
        <Text size="sm">{p.issuer}</Text>
        <Text size="xs" c="dimmed">
          Client ID: {p.client_id}
        </Text>
        <Text size="xs" c="dimmed">
          Redirect URI: {p.callback_url}
        </Text>
      </Table.Td>
      <Table.Td>{p.allowed_hds.length ? p.allowed_hds.join(', ') : 'Any account'}</Table.Td>
      <Table.Td>
        <StatusBadge tone={p.enabled ? 'ok' : 'neutral'}>{p.enabled ? 'enabled' : 'disabled'}</StatusBadge>
      </Table.Td>
      <Table.Td>
        <ManagedBy managedBy={p.managed_by} lastChangedBy={p.last_changed_by} />
      </Table.Td>
      {canWrite ? (
        <Table.Td>
          <Group gap={6} wrap="nowrap">
            <Button size="xs" variant="default" onClick={onEdit}>
              Edit<VisuallyHidden> {p.name}</VisuallyHidden>
            </Button>
            <ConfirmAction
              label={
                <>
                  Delete<VisuallyHidden> {p.name}</VisuallyHidden>
                </>
              }
              confirmLabel="Delete provider"
              title={`Delete ${p.name}?`}
              loading={del.isPending}
              onConfirm={() => del.mutateAsync(undefined).catch(() => undefined)}
            >
              <Text size="sm">
                Every sign-in account linked through {p.name} is unlinked, and users who only sign in with it lose
                access until they link another account. This cannot be undone.
              </Text>
            </ConfirmAction>
          </Group>
        </Table.Td>
      ) : null}
    </Table.Tr>
  )
}

interface FormValues {
  slug: string
  kind: 'google' | 'oidc'
  name: string
  issuer: string
  client_id: string
  client_secret: string
  allowed_hds: string[]
  scopes: string
  enabled: boolean
}

function ProviderForm({ provider, onDone }: { provider?: IdentityProvider; onDone: () => void }) {
  const editing = !!provider
  const form = useForm<FormValues>({
    initialValues: {
      slug: provider?.slug ?? '',
      kind: provider?.kind ?? 'google',
      name: provider?.name ?? '',
      issuer: provider?.issuer ?? '',
      client_id: provider?.client_id ?? '',
      client_secret: '',
      allowed_hds: provider?.allowed_hds ?? [],
      scopes: provider?.scopes ?? '',
      enabled: provider?.enabled ?? true,
    },
    validate: {
      slug: (v) =>
        editing || /^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/.test(v) ? null : 'Use 2–63 lowercase letters, digits or hyphens',
      name: (v) => (v.trim() ? null : 'Enter a name'),
      issuer: (v, all) =>
        all.kind === 'oidc' && !v.trim() ? 'Enter the issuer URL' : v && !/^https?:\/\//.test(v) ? 'Enter a URL' : null,
      client_id: (v) => (v.trim() ? null : 'Enter the client ID'),
      client_secret: (v) => (editing || v ? null : 'Enter the client secret'),
      allowed_hds: (v) => {
        const bad = v.find((d) => !domainRE.test(d))
        return bad ? `${bad} is not a domain name` : null
      },
    },
  })
  const invalidate = [installKeys.providers]
  const create = useAdminMutation({
    mutationFn: async (v: FormValues) => {
      const body: Schemas['CreateProviderRequest'] = {
        slug: v.slug,
        kind: v.kind,
        name: v.name.trim(),
        client_id: v.client_id.trim(),
        client_secret: v.client_secret,
        enabled: v.enabled,
      }
      if (v.issuer.trim()) body.issuer = v.issuer.trim()
      if (v.allowed_hds.length) body.allowed_hds = v.allowed_hds
      if (v.scopes.trim()) body.scopes = v.scopes.trim()
      return unwrap(await api.POST('/identity-providers', { body }))
    },
    success: (p) => `${p.name} added. Register its redirect URI at the provider.`,
    invalidate,
    onSuccess: onDone,
  })
  const update = useVersionedMutation({
    mutationFn: async (v: FormValues) => {
      if (!provider) throw new Error('no provider')
      const body: Schemas['UpdateProviderRequest'] = { enabled: v.enabled }
      if (v.name.trim() !== provider.name) body.name = v.name.trim()
      if (v.issuer.trim() !== provider.issuer) body.issuer = v.issuer.trim()
      if (v.client_id.trim() !== provider.client_id) body.client_id = v.client_id.trim()
      if (v.client_secret) body.client_secret = v.client_secret
      if (v.allowed_hds.join(',') !== provider.allowed_hds.join(',')) body.allowed_hds = v.allowed_hds
      if (v.scopes.trim() !== provider.scopes) body.scopes = v.scopes.trim()
      return unwrap(
        await api.PATCH('/identity-providers/{provider}', {
          params: { path: { provider: provider.id }, header: ifMatch(provider.version) },
          body,
        }),
      )
    },
    success: (p) => `${p.name} saved`,
    invalidate,
    onSuccess: onDone,
  })
  const pending = create.isPending || update.isPending
  return (
    <form
      onSubmit={form.onSubmit((v) => {
        const onError = (e: unknown) => {
          if (e instanceof ApiError)
            for (const f of e.fields) form.setFieldError(f.field.replace(/^body\./, ''), f.message)
        }
        if (editing) update.mutate(v, { onError })
        else create.mutate(v, { onError })
      })}
    >
      <Stack>
        {!editing ? (
          <Group grow align="flex-start">
            <TextInput
              label="Slug"
              description="Used in the redirect URI"
              required
              data-autofocus
              {...form.getInputProps('slug')}
            />
            <Select
              label="Kind"
              description="Protocol flavour"
              data={[
                { value: 'google', label: 'Google' },
                { value: 'oidc', label: 'OpenID Connect' },
              ]}
              allowDeselect={false}
              {...form.getInputProps('kind')}
            />
          </Group>
        ) : null}
        <TextInput
          label="Display name"
          description="Shown on the sign-in page"
          required
          {...form.getInputProps('name')}
        />
        <TextInput
          label="Issuer URL"
          description={
            form.values.kind === 'google' ? 'Leave empty for https://accounts.google.com' : 'The provider’s issuer'
          }
          required={form.values.kind === 'oidc'}
          {...form.getInputProps('issuer')}
        />
        <TextInput label="Client ID" required autoComplete="off" {...form.getInputProps('client_id')} />
        <PasswordInput
          label="Client secret"
          description={
            editing
              ? 'Leave empty to keep the stored secret; entering a value replaces it.'
              : 'Write-only: it is encrypted and never shown again.'
          }
          required={!editing}
          autoComplete="new-password"
          {...form.getInputProps('client_secret')}
        />
        <TagsInput
          label="Allowed Google Workspace domains"
          description="Only accounts from these hosted domains may sign in; empty accepts any account. Press Enter after each domain."
          placeholder="example.com"
          {...form.getInputProps('allowed_hds')}
          onChange={(v) => {
            form.setFieldValue('allowed_hds', v.map((d) => d.trim().toLowerCase()).filter(Boolean))
          }}
        />
        <TextInput
          label="Scopes"
          description="Space-separated; leave empty for the default (openid email profile)"
          {...form.getInputProps('scopes')}
        />
        <Switch
          label="Enabled"
          description="Disabled providers are hidden from the sign-in page"
          {...form.getInputProps('enabled', { type: 'checkbox' })}
        />
        <Group justify="flex-end">
          <Button variant="default" onClick={onDone}>
            Cancel
          </Button>
          <Button type="submit" loading={pending}>
            {editing ? 'Save changes' : 'Add provider'}
          </Button>
        </Group>
      </Stack>
    </form>
  )
}
