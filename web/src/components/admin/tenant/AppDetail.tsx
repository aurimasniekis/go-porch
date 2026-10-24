import { Button, Card, Divider, Group, Select, Stack, Table, Text, Title, VisuallyHidden } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { adminQuery, useAdminMutation } from '@/api/admin'
import {
  applicationQuery,
  deleteApplication,
  lines,
  rotateClientSecret,
  shareApplication,
  sharesQuery,
  tenantKeys,
  unshareApplication,
  updateApplication,
  when,
  type Application,
  type UpdateApplicationRequest,
} from '@/api/admin/tenant'
import { ConfirmButton, EmptyState, ErrorAlert } from '@/components/admin/kit'
import {
  ClientFields,
  GeneralFields,
  HeadersField,
  headerMap,
  HostsField,
  toClientConfig,
  toClientForm,
  toForwardForm,
  toGeneralForm,
} from './appForms'
import { CopyField, LoadingRows, MutationError, ProvenanceTag, Tag } from './common'
import { SecretModal, type OneTimeSecret } from './SecretModal'

/** Edits one application: connection details, settings, client, forward-auth, sharing and deletion. */
export function AppDetail({ tenant, appId, onDeleted }: { tenant: string; appId: string; onDeleted: () => void }) {
  const q = useQuery(applicationQuery(tenant, appId))
  const caps = useQuery(adminQuery)
  if (q.error) return <ErrorAlert error={q.error} />
  if (!q.data) return <LoadingRows rows={6} />
  const a = q.data
  const reload = async () => (await q.refetch()).data
  return (
    <Stack gap="lg">
      <Group gap="xs">
        <Tag variant="light">{a.kind === 'oidc' ? 'OpenID Connect' : 'Forward-auth'}</Tag>
        <Tag variant="light" color={a.enabled ? 'green' : 'gray'}>
          {a.enabled ? 'enabled' : 'disabled'}
        </Tag>
        <ProvenanceTag managedBy={a.managed_by} lastChangedBy={a.last_changed_by} />
        <Text size="xs" c="dimmed">
          Slug {a.slug} · updated {when(a.updated_at)}
        </Text>
      </Group>
      {a.client ? <Connection tenant={tenant} app={a} /> : null}
      <GeneralSection tenant={tenant} app={a} reload={reload} />
      {a.kind === 'oidc' ? <ClientSection tenant={tenant} app={a} reload={reload} /> : null}
      {a.kind === 'forward_auth' ? <ForwardSection tenant={tenant} app={a} reload={reload} /> : null}
      {caps.data?.installation ? <Shares tenant={tenant} app={a} /> : null}
      <DangerZone tenant={tenant} app={a} onDeleted={onDeleted} reload={reload} />
    </Stack>
  )
}

type Reload = () => Promise<Application | undefined>

/** Saves a partial update with the app's version, then refreshes the cached copies. */
function useAppUpdate(tenant: string, app: Application, success: string, onSaved: (a: Application) => void) {
  const qc = useQueryClient()
  return useAdminMutation({
    mutationFn: (body: UpdateApplicationRequest) => updateApplication(tenant, app, body),
    success,
    invalidate: [tenantKeys.apps(tenant)],
    onSuccess: (a) => {
      qc.setQueryData(tenantKeys.app(tenant, a.id), a)
      onSaved(a)
    },
  })
}

function SectionCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <Title order={3} size="h5" mb="sm">
        {title}
      </Title>
      {children}
    </Card>
  )
}

function Connection({ tenant, app }: { tenant: string; app: Application }) {
  const c = app.client
  const [secret, setSecret] = useState<OneTimeSecret | null>(null)
  const rotate = useAdminMutation({
    mutationFn: () => rotateClientSecret(tenant, app.id),
    success: 'New client secret issued; the old one no longer works',
    invalidate: [tenantKeys.app(tenant, app.id)],
    onSuccess: (s) => {
      setSecret({ title: `New secret for ${app.name}`, clientId: s.client_id, secret: s.client_secret })
    },
  })
  if (!c) return null
  return (
    <SectionCard title="Connection">
      <Stack gap="sm">
        <CopyField label="Issuer" value={c.issuer} />
        <CopyField label="Discovery URL" value={c.discovery_url} />
        <CopyField label="Client ID" value={c.client_id} />
        {c.client_type === 'confidential' ? (
          <Group justify="space-between" wrap="wrap">
            <Text size="sm" c="dimmed">
              Client secret {c.secret_hint ? `ending in …${c.secret_hint}` : 'set'} (never shown again)
            </Text>
            <ConfirmButton
              variant="default"
              label="Rotate secret"
              title="Issue a new client secret?"
              color="orange"
              loading={rotate.isPending}
              onConfirm={() => rotate.mutateAsync().catch(() => undefined)}
            >
              <Text size="sm">
                The current secret stops working immediately. Update the application with the new secret right away.
                This needs a recent sign-in.
              </Text>
            </ConfirmButton>
          </Group>
        ) : (
          <Text size="sm" c="dimmed">
            Public client: no secret, PKCE is always required.
          </Text>
        )}
      </Stack>
      <SecretModal
        value={secret}
        onClose={() => {
          setSecret(null)
        }}
      />
    </SectionCard>
  )
}

function GeneralSection({ tenant, app, reload }: { tenant: string; app: Application; reload: Reload }) {
  const form = useForm({
    initialValues: toGeneralForm(app),
    validate: { name: (v) => (v.trim() ? null : 'Required') },
  })
  const reset = (a: Application | undefined) => {
    if (!a) return
    form.setInitialValues(toGeneralForm(a))
    form.setValues(toGeneralForm(a))
  }
  const save = useAppUpdate(tenant, app, 'Application saved', reset)
  return (
    <SectionCard title="Settings">
      <form
        onSubmit={form.onSubmit((v) => {
          save.mutate({
            name: v.name.trim(),
            description: v.description,
            launch_url: v.launch_url.trim(),
            enabled: v.enabled,
            access_mode: v.access_mode,
            disclosure: v.disclosure,
          })
        })}
      >
        <Stack>
          <GeneralFields form={form} edit />
          <MutationError
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
          />
          <Group justify="flex-end">
            <Button type="submit" loading={save.isPending} disabled={!form.isDirty()}>
              Save settings
            </Button>
          </Group>
        </Stack>
      </form>
    </SectionCard>
  )
}

function ClientSection({ tenant, app, reload }: { tenant: string; app: Application; reload: Reload }) {
  const form = useForm({ initialValues: toClientForm(app.client) })
  const reset = (a: Application | undefined) => {
    if (!a) return
    form.setInitialValues(toClientForm(a.client))
    form.setValues(toClientForm(a.client))
  }
  const save = useAppUpdate(tenant, app, 'Client configuration saved', reset)
  return (
    <SectionCard title="OpenID Connect client">
      <form
        onSubmit={form.onSubmit((v) => {
          save.mutate({ client: toClientConfig(v, false) })
        })}
      >
        <Stack>
          <ClientFields form={form} edit />
          <MutationError
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
          />
          <Group justify="flex-end">
            <Button type="submit" loading={save.isPending} disabled={!form.isDirty()}>
              Save client
            </Button>
          </Group>
        </Stack>
      </form>
    </SectionCard>
  )
}

function ForwardSection({ tenant, app, reload }: { tenant: string; app: Application; reload: Reload }) {
  const form = useForm({
    initialValues: toForwardForm(app),
    validate: { hosts: (v) => (lines(v).length ? null : 'Add at least one host') },
  })
  const reset = (a: Application | undefined) => {
    if (!a) return
    form.setInitialValues(toForwardForm(a))
    form.setValues(toForwardForm(a))
  }
  const save = useAppUpdate(tenant, app, 'Forward-auth settings saved', reset)
  return (
    <SectionCard title="Forward-auth">
      <form
        onSubmit={form.onSubmit((v) => {
          save.mutate({ hosts: lines(v.hosts), forward_headers: headerMap(v.headers) })
        })}
      >
        <Stack>
          <HostsField form={form} />
          <HeadersField form={form} />
          <MutationError
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
          />
          <Group justify="flex-end">
            <Button type="submit" loading={save.isPending} disabled={!form.isDirty()}>
              Save forward-auth
            </Button>
          </Group>
        </Stack>
      </form>
    </SectionCard>
  )
}

/** Cross-tenant sharing (installation operators only, ADR-0004). */
function Shares({ tenant, app }: { tenant: string; app: Application }) {
  const q = useQuery(sharesQuery(tenant, app.id))
  const caps = useQuery(adminQuery)
  const [target, setTarget] = useState<string | null>(null)
  const share = useAdminMutation({
    mutationFn: (t: string) => shareApplication(tenant, app.id, t),
    success: 'Application shared',
    invalidate: [tenantKeys.shares(tenant, app.id)],
    onSuccess: () => {
      setTarget(null)
    },
  })
  const unshare = useAdminMutation({
    mutationFn: (t: string) => unshareApplication(tenant, app.id, t),
    success: 'Sharing removed',
    invalidate: [tenantKeys.shares(tenant, app.id)],
  })
  const shared = new Set(q.data?.map((s) => s.tenant_id))
  const options = (caps.data?.tenants ?? [])
    .filter((t) => t.id !== app.tenant_id && !shared.has(t.id))
    .map((t) => ({ value: t.slug, label: t.name }))
  return (
    <SectionCard title="Shared with other tenants">
      <Stack>
        <Text size="sm" c="dimmed">
          Members of a tenant this application is shared with can use it as if it were their own. Only installation
          operators can share applications across tenants.
        </Text>
        {q.error ? <ErrorAlert error={q.error} /> : null}
        {q.isPending ? (
          <LoadingRows rows={1} />
        ) : !q.data?.length ? (
          q.error ? null : (
            <EmptyState>Not shared.</EmptyState>
          )
        ) : (
          <Table aria-label="Tenants this application is shared with">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>Since</Table.Th>
                <Table.Th>
                  <VisuallyHidden>Actions</VisuallyHidden>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {q.data.map((s) => (
                <Table.Tr key={s.tenant_id}>
                  <Table.Td>
                    {s.tenant_name}{' '}
                    <Text span size="xs" c="dimmed">
                      ({s.tenant_slug})
                    </Text>
                  </Table.Td>
                  <Table.Td>{when(s.created_at)}</Table.Td>
                  <Table.Td>
                    <Group justify="flex-end">
                      <ConfirmButton
                        variant="default"
                        label="Stop sharing"
                        title={`Stop sharing with ${s.tenant_name}?`}
                        loading={unshare.isPending}
                        onConfirm={() => unshare.mutateAsync(s.tenant_slug).catch(() => undefined)}
                      >
                        <Text size="sm">Members of {s.tenant_name} lose access to this application.</Text>
                      </ConfirmButton>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
        <Group align="flex-end">
          <Select
            label="Share with tenant"
            placeholder="Choose a tenant"
            data={options}
            value={target}
            onChange={setTarget}
            searchable
            nothingFoundMessage="No other tenant"
            style={{ flex: 1 }}
            maw={360}
          />
          <Button
            variant="default"
            disabled={!target}
            loading={share.isPending}
            onClick={() => {
              if (target) share.mutate(target)
            }}
          >
            Share
          </Button>
        </Group>
      </Stack>
    </SectionCard>
  )
}

function DangerZone({
  tenant,
  app,
  onDeleted,
  reload,
}: {
  tenant: string
  app: Application
  onDeleted: () => void
  reload: Reload
}) {
  const del = useAdminMutation({
    mutationFn: () => deleteApplication(tenant, app),
    success: `Application ${app.name} deleted`,
    invalidate: [tenantKeys.apps(tenant)],
    onSuccess: onDeleted,
  })
  return (
    <Card>
      <Divider label="Danger zone" labelPosition="left" mb="sm" />
      <Stack>
        <Group justify="space-between" wrap="wrap">
          <Text size="sm">Delete the application and its OpenID Connect client (if any).</Text>
          <ConfirmButton
            variant="default"
            label="Delete application"
            title={`Delete ${app.name}?`}
            loading={del.isPending}
            onConfirm={() => del.mutateAsync().catch(() => undefined)}
          >
            <Text size="sm">People can no longer sign in to {app.name} through Porch. This cannot be undone.</Text>
          </ConfirmButton>
        </Group>
        <MutationError error={del.error} onReload={reload} />
      </Stack>
    </Card>
  )
}
