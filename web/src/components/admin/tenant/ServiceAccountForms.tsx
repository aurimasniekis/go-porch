import { Button, Code, Group, Modal, NumberInput, Stack, Switch, Text, Textarea, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { useQueryClient } from '@tanstack/react-query'
import { useAdminMutation } from '@/api/admin'
import {
  createServiceAccount,
  lines,
  serviceAccountsQuery,
  tenantKeys,
  updateServiceAccount,
  type CreatedServiceAccount,
  type ServiceAccount,
} from '@/api/admin/tenant'
import { CopyField, MutationError } from './common'

const slugRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

/** A client credentials request for a service account, as copyable shell text (rendered as text, never HTML). */
export function curlExample(tokenEndpoint: string, clientId: string, audience?: string): string {
  return [
    `curl -sS -X POST '${tokenEndpoint}' \\`,
    `  -u '${clientId}:'"$CLIENT_SECRET" \\`,
    `  -d grant_type=client_credentials \\`,
    `  --data-urlencode 'resource=${audience ?? 'https://api.example.com'}'`,
  ].join('\n')
}

export function CurlExample({ sa }: { sa: Pick<ServiceAccount, 'token_endpoint' | 'id' | 'audiences'> }) {
  const text = curlExample(sa.token_endpoint, sa.id, sa.audiences[0])
  return (
    <Stack gap={4}>
      <CopyField label="Token endpoint" value={sa.token_endpoint} />
      <Text size="sm" fw={500} mt="xs">
        Example: request an access token
      </Text>
      <Code block>{text}</Code>
      <Text size="xs" c="dimmed">
        Set CLIENT_SECRET in the environment first. The resource must be one of the account&apos;s audiences.
      </Text>
    </Stack>
  )
}

interface SAForm {
  slug: string
  name: string
  description: string
  audiences: string
  ttl: number | string
}

export function CreateServiceAccountModal({
  tenant,
  opened,
  onClose,
  onCreated,
}: {
  tenant: string
  opened: boolean
  onClose: () => void
  onCreated: (sa: CreatedServiceAccount) => void
}) {
  const form = useForm<SAForm>({
    initialValues: { slug: '', name: '', description: '', audiences: '', ttl: '' },
    validate: {
      slug: (v) => (slugRe.test(v) ? null : 'Lowercase letters, digits and dashes'),
      name: (v) => (v.trim() ? null : 'Required'),
    },
  })
  const create = useAdminMutation({
    mutationFn: (v: SAForm) =>
      createServiceAccount(tenant, {
        slug: v.slug,
        name: v.name.trim(),
        description: v.description,
        audiences: lines(v.audiences),
        ...(typeof v.ttl === 'number' && v.ttl > 0 ? { access_token_ttl_seconds: v.ttl } : {}),
      }),
    success: (sa) => `Service account ${sa.name} created`,
    invalidate: [tenantKeys.serviceAccounts(tenant)],
    onSuccess: (sa) => {
      form.reset()
      onCreated(sa)
    },
  })
  return (
    <Modal opened={opened} onClose={onClose} title="New service account" size="lg">
      <form
        onSubmit={form.onSubmit((v) => {
          create.mutate(v)
        })}
      >
        <Stack>
          <TextInput label="Slug" description="Stable identifier, lowercase" required {...form.getInputProps('slug')} />
          <TextInput label="Name" required {...form.getInputProps('name')} />
          <Textarea label="Description" autosize minRows={2} {...form.getInputProps('description')} />
          <Textarea
            label="API audiences"
            description="One per line: the resource values (RFC 8707) its access tokens may target"
            autosize
            minRows={2}
            {...form.getInputProps('audiences')}
          />
          <NumberInput
            label="Access token lifetime (seconds)"
            description="60 to 3600; empty = default (600)"
            min={60}
            max={3600}
            allowDecimal={false}
            {...form.getInputProps('ttl')}
          />
          <MutationError error={create.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Create service account
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

interface EditForm {
  name: string
  description: string
  enabled: boolean
  audiences: string
  ttl: number | string
}

const toEdit = (sa: ServiceAccount): EditForm => ({
  name: sa.name,
  description: sa.description,
  enabled: sa.enabled,
  audiences: sa.audiences.join('\n'),
  ttl: sa.access_token_ttl_seconds,
})

export function EditServiceAccountModal({
  tenant,
  sa,
  onClose,
}: {
  tenant: string
  sa: ServiceAccount
  onClose: () => void
}) {
  const qc = useQueryClient()
  const form = useForm<EditForm>({
    initialValues: toEdit(sa),
    validate: {
      name: (v) => (v.trim() ? null : 'Required'),
      ttl: (v) => (typeof v === 'number' && v >= 60 && v <= 3600 ? null : 'Between 60 and 3600 seconds'),
    },
  })
  const save = useAdminMutation({
    mutationFn: (v: EditForm) =>
      updateServiceAccount(tenant, sa, {
        name: v.name.trim(),
        description: v.description,
        enabled: v.enabled,
        audiences: lines(v.audiences),
        access_token_ttl_seconds: Number(v.ttl),
      }),
    success: (r) => `${r.name} saved`,
    invalidate: [tenantKeys.serviceAccounts(tenant)],
    onSuccess: onClose,
  })
  const reload = async () => {
    const list = await qc.query({ ...serviceAccountsQuery(tenant), staleTime: 0 })
    const fresh = list.find((x) => x.id === sa.id)
    if (fresh) {
      form.setValues(toEdit(fresh))
      form.resetDirty(toEdit(fresh))
    }
    save.reset()
  }
  return (
    <Modal opened onClose={onClose} title={`Edit ${sa.name}`} size="lg">
      <form
        onSubmit={form.onSubmit((v) => {
          save.mutate(v)
        })}
      >
        <Stack>
          <TextInput label="Name" required {...form.getInputProps('name')} />
          <Textarea label="Description" autosize minRows={2} {...form.getInputProps('description')} />
          <Switch
            label="Enabled"
            description="Disabled accounts cannot obtain tokens"
            {...form.getInputProps('enabled', { type: 'checkbox' })}
          />
          <Textarea
            label="API audiences"
            description="One per line"
            autosize
            minRows={2}
            {...form.getInputProps('audiences')}
          />
          <NumberInput
            label="Access token lifetime (seconds)"
            min={60}
            max={3600}
            allowDecimal={false}
            required
            {...form.getInputProps('ttl')}
          />
          <MutationError error={save.error} onReload={reload} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              Save
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}
