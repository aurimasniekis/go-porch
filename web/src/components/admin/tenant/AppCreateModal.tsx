import { Button, Divider, Group, Modal, SegmentedControl, Stack, Text, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useState } from 'react'
import { useAdminMutation } from '@/api/admin'
import {
  createApplication,
  lines,
  tenantKeys,
  uploadApplicationIcon,
  type CreatedApplication,
} from '@/api/admin/tenant'
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
import { MutationError } from './common'
import { fileBase64, LauncherFields, launcherUpdate, launcherValidate, toLauncherForm } from './LauncherFields'

type Kind = 'oidc' | 'forward_auth'

const slugRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** Dialog that creates an OIDC or forward-auth application. */
export function AppCreateModal({
  tenant,
  opened,
  onClose,
  onCreated,
}: {
  tenant: string
  opened: boolean
  onClose: () => void
  onCreated: (a: CreatedApplication) => void
}) {
  const [kind, setKind] = useState<Kind>('oidc')
  const slug = useForm({
    initialValues: { slug: '' },
    validate: { slug: (v) => (slugRe.test(v) ? null : 'Lowercase letters, digits and dashes') },
  })
  const general = useForm({
    initialValues: toGeneralForm(),
    validate: { name: (v) => (v.trim() ? null : 'Required') },
  })
  const client = useForm({ initialValues: toClientForm() })
  const launcher = useForm({ initialValues: toLauncherForm(), validate: (v) => launcherValidate(v, false) })
  const forward = useForm({
    initialValues: toForwardForm(),
    validate: { hosts: (v) => (kind === 'forward_auth' && lines(v).length === 0 ? 'Add at least one host' : null) },
  })
  const reset = () => {
    slug.reset()
    general.reset()
    client.reset()
    forward.reset()
    launcher.reset()
  }
  const create = useAdminMutation({
    mutationFn: async () => {
      const g = general.values
      const look = launcherUpdate(launcher.values)
      const created = await createApplication(tenant, {
        slug: slug.values.slug,
        name: g.name.trim(),
        kind,
        description: g.description,
        launch_url: g.launch_url.trim() || undefined,
        access_mode: g.access_mode,
        disclosure: g.disclosure,
        ...(kind === 'oidc'
          ? { client: toClientConfig(client.values, true) }
          : { hosts: lines(forward.values.hosts), forward_headers: headerMap(forward.values.headers) }),
        group: look.group,
        icon: look.icon,
      })
      const file = launcher.values.file
      if (launcher.values.icon_source === 'upload' && file) {
        // The secret is only in the create response: keep it even if the upload fails.
        const withIcon = await uploadApplicationIcon(tenant, created, await fileBase64(file)).catch(() => null)
        if (withIcon) return { ...created, ...withIcon, client_secret: created.client_secret }
      }
      return created
    },
    success: (a) => `Application ${a.name} created`,
    invalidate: [tenantKeys.apps(tenant)],
    onSuccess: (a) => {
      reset()
      onCreated(a)
    },
  })
  const submit = () => {
    const bad = [
      slug.validate().hasErrors,
      general.validate().hasErrors,
      forward.validate().hasErrors,
      launcher.validate().hasErrors,
    ]
    if (bad.some(Boolean)) return
    create.mutate()
  }
  return (
    <Modal opened={opened} onClose={onClose} title="New application" size="xl">
      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
        noValidate
      >
        <Stack>
          <Stack gap={4}>
            <Text size="sm" fw={500} id="app-kind-label">
              Kind
            </Text>
            <SegmentedControl
              aria-labelledby="app-kind-label"
              value={kind}
              onChange={(v) => {
                setKind(v as Kind)
              }}
              data={[
                { value: 'oidc', label: 'OpenID Connect' },
                { value: 'forward_auth', label: 'Forward-auth (reverse proxy)' },
              ]}
            />
            <Text size="xs" c="dimmed">
              {kind === 'oidc'
                ? 'The application signs people in with OpenID Connect and receives a client ID (and secret).'
                : 'A reverse proxy asks Porch before forwarding requests to the protected hosts.'}
            </Text>
          </Stack>
          <TextInput
            label="Slug"
            description="Stable identifier, lowercase (cannot be changed)"
            required
            {...slug.getInputProps('slug')}
          />
          <GeneralFields form={general} />
          <Divider label="Launcher" labelPosition="left" />
          <LauncherFields form={launcher} />
          <Divider label={kind === 'oidc' ? 'OpenID Connect client' : 'Forward-auth'} labelPosition="left" />
          {kind === 'oidc' ? (
            <ClientFields form={client} />
          ) : (
            <>
              <HostsField form={forward} />
              <HeadersField form={forward} />
            </>
          )}
          <MutationError error={create.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Create application
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
