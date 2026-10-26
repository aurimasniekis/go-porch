import { Button, Card, Fieldset, Group, Modal, NumberInput, Stack, Switch, Text, TextInput, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useDisclosure } from '@mantine/hooks'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { adminQuery, can, useAdminMutation, useAdminTenant } from '@/api/admin'
import { deleteTenant, tenantKeys, tenantQuery, updateTenant, when, type Tenant } from '@/api/admin/tenant'
import { ErrorAlert, PageHeader, ReadOnlyNote } from '@/components/admin/kit'
import { LoadingRows, MutationError, Notice, ProvenanceTag, Tag } from '@/components/admin/tenant/common'

export const Route = createFileRoute('/_app/admin/t/$tenant/settings')({
  component: SettingsPage,
})

function SettingsPage() {
  const { tenant } = Route.useParams()
  const q = useQuery(tenantQuery(tenant))
  const caps = useQuery(adminQuery)
  const operator = caps.data?.installation ?? false
  const manage = can(useAdminTenant(tenant), 'tenant:manage')
  return (
    <Stack gap="lg" maw={880}>
      <PageHeader title="Settings" description="The tenant's name and session limits." />
      {q.error ? <ErrorAlert error={q.error} /> : null}
      {q.isPending ? <LoadingRows rows={4} /> : null}
      {q.data ? (
        <>
          <Group gap="xs">
            <Tag variant="light" color={q.data.status === 'active' ? 'green' : 'red'}>
              {q.data.status}
            </Tag>
            <ProvenanceTag managedBy={q.data.managed_by} lastChangedBy={q.data.last_changed_by} />
            <Text size="xs" c="dimmed">
              Slug {q.data.slug} · ID {q.data.id} · updated {when(q.data.updated_at)}
            </Text>
          </Group>
          {manage ? null : <ReadOnlyNote what="this tenant's settings" mb={0} />}
          <SettingsForm
            key={q.data.id}
            t={q.data}
            operator={operator}
            readOnly={!manage}
            reload={async () => (await q.refetch()).data}
          />
          {operator ? <DeleteTenant t={q.data} /> : null}
        </>
      ) : null}
    </Stack>
  )
}

interface Values {
  name: string
  idleMinutes: number | string
  absoluteHours: number | string
  enabled: boolean
}

const toValues = (t: Tenant): Values => ({
  name: t.name,
  idleMinutes: t.session_idle_seconds ? t.session_idle_seconds / 60 : 0,
  absoluteHours: t.session_absolute_seconds ? t.session_absolute_seconds / 3600 : 0,
  enabled: t.status === 'active',
})

function SettingsForm({
  t,
  operator,
  readOnly,
  reload,
}: {
  t: Tenant
  operator: boolean
  /** Shows the settings without letting them be changed (no tenant:manage). */
  readOnly: boolean
  reload: () => Promise<Tenant | undefined>
}) {
  const form = useForm<Values>({
    initialValues: toValues(t),
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      idleMinutes: (v) => (Number(v) >= 0 ? null : 'Must be zero or more'),
      absoluteHours: (v) => (Number(v) >= 0 ? null : 'Must be zero or more'),
    },
  })
  const reset = (fresh: Tenant | undefined) => {
    if (!fresh) return
    form.setValues(toValues(fresh))
    form.resetDirty(toValues(fresh))
  }
  const save = useAdminMutation({
    mutationFn: (v: Values) => {
      const idle = Math.round(Number(v.idleMinutes) * 60)
      const abs = Math.round(Number(v.absoluteHours) * 3600)
      return updateTenant(t.slug, t.version, {
        ...(v.name.trim() !== t.name ? { name: v.name.trim() } : {}),
        ...(idle !== (t.session_idle_seconds ?? 0) ? { session_idle_seconds: idle } : {}),
        ...(abs !== (t.session_absolute_seconds ?? 0) ? { session_absolute_seconds: abs } : {}),
        ...(operator && v.enabled !== (t.status === 'active') ? { status: v.enabled ? 'active' : 'disabled' } : {}),
      })
    },
    success: 'Tenant settings saved',
    invalidate: [tenantKeys.tenant(t.slug), adminQuery.queryKey],
    onSuccess: (fresh) => {
      reset(fresh)
    },
  })
  return (
    <Card>
      <form
        onSubmit={form.onSubmit((v) => {
          save.mutate(v)
        })}
      >
        <Stack>
          <Fieldset disabled={readOnly} variant="unstyled" p={0} m={0}>
            <Stack>
              <TextInput label="Tenant name" required {...form.getInputProps('name')} />
              <Title order={2} size="h5" mt="sm">
                Session limits
              </Title>
              <Text size="sm" c="dimmed">
                Shorten how long members' sessions last. 0 uses the installation default. A session belongs to the
                person, not the tenant, so members of several tenants get the strictest limits; overrides never lengthen
                sessions. New limits apply from the next sign-in.
              </Text>
              <Group grow align="flex-start" wrap="wrap">
                <NumberInput
                  label="Idle timeout (minutes)"
                  description="Sign out after this much inactivity"
                  min={0}
                  allowNegative={false}
                  {...form.getInputProps('idleMinutes')}
                />
                <NumberInput
                  label="Absolute lifetime (hours)"
                  description="Sign out after this long regardless of activity"
                  min={0}
                  allowNegative={false}
                  decimalScale={2}
                  {...form.getInputProps('absoluteHours')}
                />
              </Group>
              {operator ? (
                <Switch
                  label="Tenant enabled"
                  description="A disabled tenant's members cannot sign in to its applications (installation operators only)"
                  {...form.getInputProps('enabled', { type: 'checkbox' })}
                />
              ) : null}
            </Stack>
          </Fieldset>
          {readOnly ? null : (
            <>
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
            </>
          )}
        </Stack>
      </form>
    </Card>
  )
}

/** Deleting a tenant removes everything it owns; the slug must be typed to confirm (operators only). */
function DeleteTenant({ t }: { t: Tenant }) {
  const [opened, { open, close }] = useDisclosure(false)
  const [typed, setTyped] = useState('')
  const navigate = useNavigate()
  const del = useAdminMutation({
    mutationFn: () => deleteTenant(t.slug, t.version),
    success: `Tenant ${t.name} deleted`,
    invalidate: [adminQuery.queryKey],
    onSuccess: () => {
      close()
      void navigate({ to: '/admin' })
    },
  })
  return (
    <Card>
      <Stack>
        <Title order={2} size="h5">
          Danger zone
        </Title>
        <Group justify="space-between" wrap="wrap">
          <Text size="sm">
            Delete this tenant with its members, applications, service accounts, roles and policies.
          </Text>
          <Button color="red" variant="default" size="xs" onClick={open}>
            Delete tenant
          </Button>
        </Group>
      </Stack>
      <Modal
        opened={opened}
        onClose={() => {
          close()
          setTyped('')
        }}
        title={`Delete ${t.name}?`}
        centered
      >
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (typed === t.slug) del.mutate()
          }}
        >
          <Stack>
            <Notice color="red" title="This cannot be undone">
              Everything the tenant owns is deleted and its members lose access to its applications.
            </Notice>
            <TextInput
              label={`Type ${t.slug} to confirm`}
              value={typed}
              onChange={(e) => {
                setTyped(e.currentTarget.value)
              }}
              autoComplete="off"
              data-autofocus
            />
            <MutationError error={del.error} />
            <Group justify="flex-end">
              <Button variant="default" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" color="red" disabled={typed !== t.slug} loading={del.isPending}>
                Delete tenant
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Card>
  )
}
