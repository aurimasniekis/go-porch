import {
  Button,
  Card,
  Divider,
  Fieldset,
  Group,
  Select,
  Stack,
  Table,
  Text,
  Title,
  VisuallyHidden,
} from '@mantine/core'
import { useForm } from '@mantine/form'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { adminQuery, can, readsInstallationConfig, useAdminMutation, useAdminTenant } from '@/api/admin'
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
  uploadApplicationIcon,
  when,
  type Application,
  type UpdateApplicationRequest,
} from '@/api/admin/tenant'
import { ConfirmButton, EmptyState, ErrorAlert, ReadOnlyNote } from '@/components/admin/kit'
import { ListTable } from '@/components/ListTable'
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
import {
  fileBase64,
  LauncherFields,
  launcherUpdate,
  launcherValidate,
  toLauncherForm,
  type LauncherForm,
} from './LauncherFields'
import { SecretModal, type OneTimeSecret } from './SecretModal'

/**
 * Edits one application: connection details, settings, client, forward-auth, sharing and deletion. Without app:manage
 * everything is shown read-only; sharing is listed for installation operators and inspectors and changed by operators.
 */
export function AppDetail({ tenant, appId, onDeleted }: { tenant: string; appId: string; onDeleted: () => void }) {
  const q = useQuery(applicationQuery(tenant, appId))
  const t = useAdminTenant(tenant)
  const manage = can(t, 'app:manage')
  const readOnly = !manage
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
      {readOnly ? <ReadOnlyNote what="this application" mb={0} /> : null}
      {a.client ? <Connection tenant={tenant} app={a} readOnly={readOnly} /> : null}
      <GeneralSection tenant={tenant} app={a} reload={reload} readOnly={readOnly} />
      <LauncherSection tenant={tenant} app={a} reload={reload} readOnly={readOnly} />
      {a.kind === 'oidc' ? <ClientSection tenant={tenant} app={a} reload={reload} readOnly={readOnly} /> : null}
      {a.kind === 'forward_auth' ? (
        <ForwardSection tenant={tenant} app={a} reload={reload} readOnly={readOnly} />
      ) : null}
      {readsInstallationConfig(t) ? <Shares tenant={tenant} app={a} manage={t?.via === 'operator'} /> : null}
      {manage ? <DangerZone tenant={tenant} app={a} onDeleted={onDeleted} reload={reload} /> : null}
    </Stack>
  )
}

type Reload = () => Promise<Application | undefined>

interface SectionProps {
  tenant: string
  app: Application
  reload: Reload
  /** Shows the values without letting them be changed (no app:manage). */
  readOnly: boolean
}

/** The form's inputs; disabled (shown as values) when read-only. */
function Fields({ readOnly, children }: { readOnly: boolean; children: ReactNode }) {
  return (
    <Fieldset disabled={readOnly} variant="unstyled" p={0} m={0}>
      {children}
    </Fieldset>
  )
}

/** The save row of a section form (hidden when read-only). */
function SaveRow({
  readOnly,
  error,
  onReload,
  loading,
  dirty,
  label,
}: {
  readOnly: boolean
  error: unknown
  onReload: () => Promise<void>
  loading: boolean
  dirty: boolean
  label: string
}) {
  if (readOnly) return null
  return (
    <>
      <MutationError error={error} onReload={onReload} />
      <Group justify="flex-end">
        <Button type="submit" loading={loading} disabled={!dirty}>
          {label}
        </Button>
      </Group>
    </>
  )
}

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

function Connection({ tenant, app, readOnly }: { tenant: string; app: Application; readOnly: boolean }) {
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
            {readOnly ? null : (
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
            )}
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

function GeneralSection({ tenant, app, reload, readOnly }: SectionProps) {
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
          <Fields readOnly={readOnly}>
            <GeneralFields form={form} edit />
          </Fields>
          <SaveRow
            readOnly={readOnly}
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
            loading={save.isPending}
            dirty={form.isDirty()}
            label="Save settings"
          />
        </Stack>
      </form>
    </SectionCard>
  )
}

function LauncherSection({ tenant, app, reload, readOnly }: SectionProps) {
  const qc = useQueryClient()
  const form = useForm({
    initialValues: toLauncherForm(app),
    validate: (v) => launcherValidate(v, app.icon_source === 'upload'),
  })
  const reset = (a: Application | undefined) => {
    if (!a) return
    form.setInitialValues(toLauncherForm(a))
    form.setValues(toLauncherForm(a))
  }
  const save = useAdminMutation({
    mutationFn: async (v: LauncherForm) => {
      let a = await updateApplication(tenant, app, launcherUpdate(v, app))
      if (v.icon_source === 'upload' && v.file) a = await uploadApplicationIcon(tenant, a, await fileBase64(v.file))
      return a
    },
    success: 'Launcher settings saved',
    invalidate: [tenantKeys.apps(tenant), ['my-apps']],
    onSuccess: (a) => {
      qc.setQueryData(tenantKeys.app(tenant, a.id), a)
      reset(a)
    },
  })
  return (
    <SectionCard title="Launcher">
      <form
        onSubmit={form.onSubmit((v) => {
          save.mutate(v)
        })}
      >
        <Stack>
          <Fields readOnly={readOnly}>
            <LauncherFields form={form} current={app} />
          </Fields>
          <SaveRow
            readOnly={readOnly}
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
            loading={save.isPending}
            dirty={form.isDirty()}
            label="Save launcher settings"
          />
        </Stack>
      </form>
    </SectionCard>
  )
}

function ClientSection({ tenant, app, reload, readOnly }: SectionProps) {
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
          <Fields readOnly={readOnly}>
            <ClientFields form={form} edit />
          </Fields>
          <SaveRow
            readOnly={readOnly}
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
            loading={save.isPending}
            dirty={form.isDirty()}
            label="Save client"
          />
        </Stack>
      </form>
    </SectionCard>
  )
}

function ForwardSection({ tenant, app, reload, readOnly }: SectionProps) {
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
          <Fields readOnly={readOnly}>
            <Stack>
              <HostsField form={form} />
              <HeadersField form={form} readOnly={readOnly} />
            </Stack>
          </Fields>
          <SaveRow
            readOnly={readOnly}
            error={save.error}
            onReload={async () => {
              reset(await reload())
              save.reset()
            }}
            loading={save.isPending}
            dirty={form.isDirty()}
            label="Save forward-auth"
          />
        </Stack>
      </form>
    </SectionCard>
  )
}

/** Cross-tenant sharing (installation operators change it, ADR-0004; inspectors read it, ADR-0048). */
function Shares({ tenant, app, manage }: { tenant: string; app: Application; manage: boolean }) {
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
          <ListTable aria-label="Tenants this application is shared with">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>Since</Table.Th>
                {manage ? (
                  <Table.Th>
                    <VisuallyHidden>Actions</VisuallyHidden>
                  </Table.Th>
                ) : null}
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
                  {manage ? (
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
                  ) : null}
                </Table.Tr>
              ))}
            </Table.Tbody>
          </ListTable>
        )}
        {manage ? (
          <Group align="flex-end">
            <Select
              label="Share with tenant"
              placeholder="Choose a tenant"
              data={options}
              value={target}
              onChange={setTarget}
              searchable
              nothingFoundMessage="No other tenant"
              style={{ flex: 1, minWidth: 220 }}
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
        ) : null}
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
