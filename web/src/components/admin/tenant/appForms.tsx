import {
  ActionIcon,
  Button,
  Checkbox,
  Group,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
} from '@mantine/core'
import type { UseFormReturnType } from '@mantine/form'
import { IconPlus, IconTrash } from '@tabler/icons-react'
import { lines, type Application, type ClientConfig, type Disclosure, type OIDCClient } from '@/api/admin/tenant'

// ---- general ----

export interface GeneralForm {
  name: string
  description: string
  launch_url: string
  access_mode: Application['access_mode']
  enabled: boolean
  disclosure: Disclosure
}

export function toGeneralForm(a?: Application): GeneralForm {
  return {
    name: a?.name ?? '',
    description: a?.description ?? '',
    launch_url: a?.launch_url ?? '',
    access_mode: a?.access_mode ?? 'all_members',
    enabled: a?.enabled ?? true,
    disclosure: a?.disclosure ?? { email: true, groups: false, roles: false, entitlements: false },
  }
}

const accessModes = [
  { value: 'all_members', label: 'All tenant members' },
  { value: 'assigned', label: 'Only assigned users (app:access)' },
]

const disclosureLabels: { key: keyof Disclosure; label: string }[] = [
  { key: 'email', label: 'Email address' },
  { key: 'groups', label: 'Group memberships' },
  { key: 'roles', label: 'Roles' },
  { key: 'entitlements', label: 'Entitlements' },
]

export function GeneralFields({ form, edit }: { form: UseFormReturnType<GeneralForm>; edit?: boolean }) {
  return (
    <Stack>
      <TextInput label="Name" required {...form.getInputProps('name')} />
      <Textarea label="Description" autosize minRows={2} maxRows={5} {...form.getInputProps('description')} />
      <TextInput
        label="Launch URL"
        description="Where the launcher sends people (optional for OIDC, recommended for forward-auth)"
        placeholder="https://app.example.com/"
        {...form.getInputProps('launch_url')}
      />
      <Select
        label="Who can use it"
        data={accessModes}
        allowDeselect={false}
        description="Assigned: grant app:access on this application on the Assignments page"
        {...form.getInputProps('access_mode')}
      />
      <Checkbox.Group
        label="Released to the application"
        description="Optional claims (the subject identifier, name and tenant are always released)"
        value={disclosureLabels.filter((d) => form.values.disclosure[d.key]).map((d) => d.key)}
        onChange={(v) => {
          form.setFieldValue('disclosure', {
            email: v.includes('email'),
            groups: v.includes('groups'),
            roles: v.includes('roles'),
            entitlements: v.includes('entitlements'),
          })
        }}
      >
        <Group mt="xs">
          {disclosureLabels.map((d) => (
            <Checkbox key={d.key} value={d.key} label={d.label} />
          ))}
        </Group>
      </Checkbox.Group>
      {edit ? (
        <Switch
          label="Enabled"
          description="Disabled applications cannot sign anyone in"
          {...form.getInputProps('enabled', { type: 'checkbox' })}
        />
      ) : null}
    </Stack>
  )
}

// ---- OIDC client ----

export interface ClientForm {
  client_type: 'confidential' | 'public'
  application_type: 'web' | 'native' | 'user_agent'
  redirect_uris: string
  post_logout_redirect_uris: string
  grant_types: string[]
  allowed_scopes: string[]
  audiences: string
  allowed_origins: string
  require_pkce: boolean
  signing_alg: 'ES256' | 'RS256'
  access_token_ttl_seconds: number
  id_token_ttl_seconds: number
  refresh_ttl_seconds: number
  refresh_idle_seconds: number
}

export function toClientForm(c?: OIDCClient): ClientForm {
  return {
    client_type: c?.client_type ?? 'confidential',
    application_type: c?.application_type ?? 'web',
    redirect_uris: (c?.redirect_uris ?? []).join('\n'),
    post_logout_redirect_uris: (c?.post_logout_redirect_uris ?? []).join('\n'),
    grant_types: c?.grant_types ?? ['authorization_code', 'refresh_token'],
    allowed_scopes: c?.allowed_scopes ?? ['openid', 'profile', 'email', 'offline_access'],
    audiences: (c?.audiences ?? []).join('\n'),
    allowed_origins: (c?.allowed_origins ?? []).join('\n'),
    require_pkce: c?.require_pkce ?? true,
    signing_alg: c?.signing_alg ?? 'ES256',
    access_token_ttl_seconds: c?.access_token_ttl_seconds ?? 0,
    id_token_ttl_seconds: c?.id_token_ttl_seconds ?? 0,
    refresh_ttl_seconds: c?.refresh_ttl_seconds ?? 0,
    refresh_idle_seconds: c?.refresh_idle_seconds ?? 0,
  }
}

/** Builds the client configuration; client and application type are sent only on create. */
export function toClientConfig(f: ClientForm, create: boolean): ClientConfig {
  const ttl = (n: number) => (n > 0 ? n : undefined)
  return {
    ...(create ? { client_type: f.client_type, application_type: f.application_type } : {}),
    redirect_uris: lines(f.redirect_uris),
    post_logout_redirect_uris: lines(f.post_logout_redirect_uris),
    grant_types: f.grant_types,
    allowed_scopes: f.allowed_scopes,
    audiences: lines(f.audiences),
    allowed_origins: lines(f.allowed_origins),
    require_pkce: f.client_type === 'public' ? true : f.require_pkce,
    signing_alg: f.signing_alg,
    access_token_ttl_seconds: ttl(f.access_token_ttl_seconds),
    id_token_ttl_seconds: ttl(f.id_token_ttl_seconds),
    refresh_ttl_seconds: ttl(f.refresh_ttl_seconds),
    refresh_idle_seconds: ttl(f.refresh_idle_seconds),
  }
}

const grants = [
  { value: 'authorization_code', label: 'Authorization code' },
  { value: 'refresh_token', label: 'Refresh token' },
  { value: 'client_credentials', label: 'Client credentials (confidential only)' },
]
const scopes = ['openid', 'profile', 'email', 'offline_access', 'groups']

function TtlInput({
  form,
  field,
  label,
}: {
  form: UseFormReturnType<ClientForm>
  field: keyof ClientForm
  label: string
}) {
  return (
    <NumberInput
      label={label}
      description="Seconds; 0 = default"
      min={0}
      allowDecimal={false}
      allowNegative={false}
      {...form.getInputProps(field)}
    />
  )
}

export function ClientFields({ form, edit }: { form: UseFormReturnType<ClientForm>; edit?: boolean }) {
  const isPublic = form.values.client_type === 'public'
  return (
    <Stack>
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <Select
          label="Client type"
          description={
            edit ? 'Fixed after creation' : 'Confidential clients hold a secret; public clients (SPA, mobile) use PKCE'
          }
          data={[
            { value: 'confidential', label: 'Confidential (server-side)' },
            { value: 'public', label: 'Public (no secret)' },
          ]}
          allowDeselect={false}
          disabled={edit}
          {...form.getInputProps('client_type')}
        />
        <Select
          label="Application type"
          description={edit ? 'Fixed after creation' : 'Native allows custom URI schemes and loopback ports'}
          data={[
            { value: 'web', label: 'Web' },
            { value: 'native', label: 'Native' },
            { value: 'user_agent', label: 'Browser (user agent)' },
          ]}
          allowDeselect={false}
          disabled={edit}
          {...form.getInputProps('application_type')}
        />
      </SimpleGrid>
      <Textarea
        label="Redirect URIs"
        description="One per line, matched exactly. https only (http allowed for loopback)."
        autosize
        minRows={2}
        {...form.getInputProps('redirect_uris')}
      />
      <Textarea
        label="Post-logout redirect URIs"
        description="One per line"
        autosize
        minRows={1}
        {...form.getInputProps('post_logout_redirect_uris')}
      />
      <Checkbox.Group label="Grant types" {...form.getInputProps('grant_types')}>
        <Group mt="xs">
          {grants.map((g) => (
            <Checkbox
              key={g.value}
              value={g.value}
              label={g.label}
              disabled={isPublic && g.value === 'client_credentials'}
            />
          ))}
        </Group>
      </Checkbox.Group>
      <Checkbox.Group label="Allowed scopes" {...form.getInputProps('allowed_scopes')}>
        <Group mt="xs">
          {scopes.map((s) => (
            <Checkbox key={s} value={s} label={s} />
          ))}
        </Group>
      </Checkbox.Group>
      <Textarea
        label="API audiences"
        description="One per line: resource indicators (RFC 8707) access tokens may be issued for"
        autosize
        minRows={1}
        {...form.getInputProps('audiences')}
      />
      <Textarea
        label="Allowed origins"
        description="One per line, for browser clients calling the token endpoint (e.g. https://app.example.com)"
        autosize
        minRows={1}
        {...form.getInputProps('allowed_origins')}
      />
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <Switch
          label="Require PKCE"
          description={isPublic ? 'Always required for public clients' : 'Recommended for every client'}
          disabled={isPublic}
          checked={isPublic || form.values.require_pkce}
          onChange={(e) => {
            form.setFieldValue('require_pkce', e.currentTarget.checked)
          }}
        />
        <Select
          label="ID token signing algorithm"
          data={['ES256', 'RS256']}
          allowDeselect={false}
          {...form.getInputProps('signing_alg')}
        />
      </SimpleGrid>
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <TtlInput form={form} field="access_token_ttl_seconds" label="Access token lifetime" />
        <TtlInput form={form} field="id_token_ttl_seconds" label="ID token lifetime" />
        <TtlInput form={form} field="refresh_ttl_seconds" label="Refresh token lifetime" />
        <TtlInput form={form} field="refresh_idle_seconds" label="Refresh token idle timeout" />
      </SimpleGrid>
    </Stack>
  )
}

// ---- forward-auth ----

export interface HeaderRow {
  name: string
  claim: string
}

export interface ForwardForm {
  hosts: string
  headers: HeaderRow[]
}

export function toForwardForm(a?: Application): ForwardForm {
  return {
    hosts: (a?.hosts ?? []).join('\n'),
    headers: Object.entries(a?.forward_headers ?? {}).map(([name, claim]) => ({ name, claim })),
  }
}

export function headerMap(rows: HeaderRow[]): Record<string, string> {
  return Object.fromEntries(rows.filter((r) => r.name.trim()).map((r) => [r.name.trim(), r.claim]))
}

const claims = ['sub', 'email', 'name', 'groups', 'tenant', 'roles']

export function HostsField({ form }: { form: UseFormReturnType<ForwardForm> }) {
  return (
    <Textarea
      label="Protected hosts"
      description="One host name per line (no scheme or port), e.g. wiki.example.com"
      required
      autosize
      minRows={2}
      {...form.getInputProps('hosts')}
    />
  )
}

/** The identity headers; readOnly hides the add and remove buttons. */
export function HeadersField({ form, readOnly }: { form: UseFormReturnType<ForwardForm>; readOnly?: boolean }) {
  return (
    <Stack gap="xs">
      <Text size="sm" fw={500}>
        Identity headers
      </Text>
      <Text size="xs" c="dimmed">
        Headers sent to the protected service and the claim each carries. Leave empty to send the defaults
        (X-Porch-User, X-Porch-Email, X-Porch-Name, X-Porch-Groups, X-Porch-Tenant).
      </Text>
      {form.values.headers.map((_, i) => (
        <Group key={i} align="flex-end" wrap="nowrap">
          <TextInput
            label={`Header ${i + 1} name`}
            placeholder="X-Remote-User"
            style={{ flex: 1 }}
            {...form.getInputProps(`headers.${i}.name`)}
          />
          <Select
            label={`Header ${i + 1} claim`}
            data={claims}
            allowDeselect={false}
            w={140}
            {...form.getInputProps(`headers.${i}.claim`)}
          />
          {readOnly ? null : (
            <ActionIcon
              variant="subtle"
              color="red"
              size="lg"
              aria-label={`Remove header ${i + 1}`}
              onClick={() => {
                form.removeListItem('headers', i)
              }}
            >
              <IconTrash size={16} />
            </ActionIcon>
          )}
        </Group>
      ))}
      {readOnly ? null : (
        <Group>
          <Button
            variant="default"
            size="xs"
            leftSection={<IconPlus size={14} />}
            onClick={() => {
              form.insertListItem('headers', { name: '', claim: 'sub' })
            }}
          >
            Add header
          </Button>
        </Group>
      )}
    </Stack>
  )
}
