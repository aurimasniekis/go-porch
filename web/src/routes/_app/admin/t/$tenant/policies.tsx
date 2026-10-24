import {
  Accordion,
  Alert,
  Button,
  Code,
  Group,
  Radio,
  Stack,
  Table,
  Text,
  Textarea,
  TextInput,
  Modal,
} from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { IconCheck, IconLock, IconPlus } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState, type ReactNode } from 'react'
import { ifMatch, useAdminMutation } from '@/api/admin'
import {
  authzInvalidate,
  conflictAware,
  permissionsQuery,
  policiesQuery,
  validatePolicyQuery,
  type PolicyDef,
} from '@/api/admin/authz'
import { api, check, unwrap } from '@/api/client'
import { LoadingState, ManagedBy, MutationError, Perm, Tag } from '@/components/admin/authz/common'
import { PermissionPicker } from '@/components/admin/authz/inputs'
import { slugify, validSlug } from '@/components/admin/authz/logic'
import { ConfirmButton, EmptyState, ErrorAlert, PageHeader } from '@/components/admin/kit'

export const Route = createFileRoute('/_app/admin/t/$tenant/policies')({
  component: PoliciesPage,
})

type Effect = 'condition' | 'deny'
type OpenDialog = { kind: 'create' } | { kind: 'edit'; policy: PolicyDef } | null

const MAX_EXPRESSION = 2048

function PoliciesPage() {
  const { tenant } = Route.useParams()
  const policies = useQuery(policiesQuery(tenant))
  const [dialog, setDialog] = useState<OpenDialog>(null)
  const del = useAdminMutation({
    mutationFn: async (p: PolicyDef) => {
      check(await api.DELETE('/tenants/{tenant}/policies/{policy}', { params: { path: { tenant, policy: p.id } } }))
    },
    success: 'Policy deleted',
    invalidate: authzInvalidate(tenant),
  })
  return (
    <>
      <PageHeader
        title="Policies"
        description="Condition policies restrict the assignments that reference them; deny policies override grants for their actions. Expressions use the expr language over the v1 environment."
        actions={
          <Button
            leftSection={<IconPlus size={16} aria-hidden />}
            onClick={() => {
              setDialog({ kind: 'create' })
            }}
          >
            New policy
          </Button>
        }
      />
      <Alert color="gray" icon={<IconLock size={18} />} mb="md">
        Creating, changing or deleting a policy needs a recent sign-in; you may be asked to sign in again.
      </Alert>
      <ErrorAlert error={policies.error} title="Could not load policies" />
      {policies.isPending ? <LoadingState label="Loading policies…" /> : null}
      {policies.data?.length === 0 ? <EmptyState>No policies yet.</EmptyState> : null}
      {policies.data && policies.data.length > 0 ? (
        <Table.ScrollContainer minWidth={820}>
          <Table striped highlightOnHover aria-label="Policies" verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Policy</Table.Th>
                <Table.Th>Effect</Table.Th>
                <Table.Th>Applies to</Table.Th>
                <Table.Th>Expression</Table.Th>
                <Table.Th>Managed by</Table.Th>
                <Table.Th>
                  <span className="visually-hidden">Actions</span>
                </Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {policies.data.map((p) => (
                <Table.Tr key={p.id}>
                  <Table.Td>
                    <Text fw={500}>{p.name}</Text>
                    <Text size="xs" c="dimmed">
                      {p.slug} · env v{p.env_version}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Tag color={p.effect === 'deny' ? 'red' : 'violet'}>{p.effect}</Tag>
                  </Table.Td>
                  <Table.Td>
                    {p.effect === 'deny' ? (
                      <Group gap={4}>
                        {p.actions.map((a) => (
                          <Perm key={a}>{a}</Perm>
                        ))}
                      </Group>
                    ) : (
                      <Text size="sm" c="dimmed">
                        assignments that reference it
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td maw={360}>
                    <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                      {p.expression.length > 160 ? `${p.expression.slice(0, 160)}…` : p.expression}
                    </Code>
                  </Table.Td>
                  <Table.Td>
                    <ManagedBy managedBy={p.managed_by} />
                  </Table.Td>
                  <Table.Td>
                    <Group gap="xs" justify="flex-end" wrap="nowrap">
                      <Button
                        size="xs"
                        variant="default"
                        aria-label={`Edit policy ${p.name}`}
                        onClick={() => {
                          setDialog({ kind: 'edit', policy: p })
                        }}
                      >
                        Edit
                      </Button>
                      <ConfirmButton
                        variant="default"
                        label="Delete"
                        title={`Delete policy ${p.name}?`}
                        confirmLabel="Delete policy"
                        loading={del.isPending}
                        onConfirm={() => del.mutateAsync(p).catch(() => undefined)}
                      >
                        <Text size="sm">
                          {p.effect === 'condition'
                            ? 'Every conditional assignment that references this policy is removed as well.'
                            : 'Its restriction is lifted: grants for its actions apply again.'}{' '}
                          This cannot be undone.
                        </Text>
                      </ConfirmButton>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : null}
      {dialog ? (
        <PolicyDialog
          tenant={tenant}
          policy={dialog.kind === 'edit' ? dialog.policy : undefined}
          onClose={() => {
            setDialog(null)
          }}
        />
      ) : null}
    </>
  )
}

function PolicyDialog({ tenant, policy, onClose }: { tenant: string; policy?: PolicyDef; onClose: () => void }) {
  const [name, setName] = useState(policy?.name ?? '')
  const [slug, setSlug] = useState(policy?.slug ?? '')
  const [slugTouched, setSlugTouched] = useState(false)
  const [effect, setEffect] = useState<Effect>(policy?.effect === 'deny' ? 'deny' : 'condition')
  const [actions, setActions] = useState<string[]>(policy?.actions ?? [])
  const [expression, setExpression] = useState(policy?.expression ?? '')
  const [submitted, setSubmitted] = useState(false)
  const [debounced] = useDebouncedValue(expression, 400)
  const catalogue = useQuery({ ...permissionsQuery(tenant), retry: false })
  const validation = useQuery({ ...validatePolicyQuery(tenant, debounced), enabled: debounced.trim() !== '' })
  const settled = debounced === expression && !validation.isFetching
  const compileError =
    settled && validation.data && !validation.data.valid ? (validation.data.error ?? 'Invalid') : null
  const tooLong = expression.length > MAX_EXPRESSION

  const save = useAdminMutation({
    mutationFn: async () => {
      const body = {
        name: name.trim(),
        effect,
        expression,
        ...(effect === 'deny' ? { actions } : { actions: [] }),
      }
      if (policy) {
        return conflictAware(
          (async () =>
            unwrap(
              await api.PUT('/tenants/{tenant}/policies/{policy}', {
                params: { path: { tenant, policy: policy.id }, header: ifMatch(policy.version) },
                body,
              }),
            ))(),
        )
      }
      return unwrap(
        await api.POST('/tenants/{tenant}/policies', { params: { path: { tenant } }, body: { ...body, slug } }),
      )
    },
    success: (p) => (policy ? `Policy ${p.name} saved` : `Policy ${p.name} created`),
    invalidate: authzInvalidate(tenant),
    onSuccess: onClose,
  })

  const errors = {
    name: !name.trim() ? 'Required' : null,
    slug: !policy && !validSlug(slug) ? 'Lowercase letters, digits and inner hyphens' : null,
    expression: !expression.trim() ? 'Required' : tooLong ? `At most ${MAX_EXPRESSION} characters` : null,
    actions: effect === 'deny' && actions.length === 0 ? 'A deny policy needs at least one action (or *)' : null,
  }
  const expressionError = (submitted ? errors.expression : tooLong ? errors.expression : null) ?? compileError

  return (
    <Modal centered opened onClose={onClose} title={policy ? `Edit policy ${policy.name}` : 'New policy'} size="xl">
      <form
        onSubmit={(e) => {
          e.preventDefault()
          setSubmitted(true)
          if (Object.values(errors).some(Boolean) || compileError) return
          save.mutate()
        }}
      >
        <Stack>
          <TextInput
            label="Name"
            required
            data-autofocus
            value={name}
            maxLength={200}
            error={submitted ? errors.name : null}
            onChange={(e) => {
              const v = e.currentTarget.value
              setName(v)
              if (!policy && !slugTouched) setSlug(slugify(v))
            }}
          />
          {policy ? null : (
            <TextInput
              label="Slug"
              required
              value={slug}
              maxLength={63}
              error={submitted ? errors.slug : null}
              onChange={(e) => {
                setSlugTouched(true)
                setSlug(e.currentTarget.value)
              }}
            />
          )}
          <Radio.Group
            label="Effect"
            description="A condition policy is attached to assignments and must be true for them to apply. A deny policy overrides every grant for its actions when true (or when it fails to evaluate)."
            value={effect}
            onChange={(v) => {
              setEffect(v as Effect)
            }}
          >
            <Group mt={6}>
              <Radio value="condition" label="Condition" />
              <Radio value="deny" label="Deny" />
            </Group>
          </Radio.Group>
          {effect === 'deny' ? (
            <>
              <PermissionPicker
                label="Actions"
                description="Permissions this deny policy applies to; * applies it to every action."
                value={actions}
                onChange={setActions}
                system={catalogue.data?.system}
                custom={catalogue.data?.custom}
                allowStar
              />
              {submitted && errors.actions ? (
                <Text size="sm" c="red" role="alert">
                  {errors.actions}
                </Text>
              ) : null}
            </>
          ) : null}
          <Textarea
            label="Expression"
            description={'A boolean expression, e.g. context.network == "trusted" && inGroup(principal, "ops")'}
            required
            value={expression}
            autosize
            minRows={4}
            maxRows={16}
            spellCheck={false}
            autoComplete="off"
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            error={expressionError}
            onChange={(e) => {
              setExpression(e.currentTarget.value)
            }}
          />
          <ValidationStatus
            empty={!expression.trim()}
            checking={!settled}
            valid={settled && validation.data?.valid === true}
            failed={validation.error}
          />
          <EnvironmentReference />
          <MutationError error={save.error} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              {policy ? 'Save policy' : 'Create policy'}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  )
}

function ValidationStatus({
  empty,
  checking,
  valid,
  failed,
}: {
  empty: boolean
  checking: boolean
  valid: boolean
  failed: unknown
}) {
  let content: ReactNode = null
  if (failed) content = <Text size="sm">Could not check the expression: {(failed as Error).message}</Text>
  else if (empty) content = null
  else if (checking)
    content = (
      <Text size="sm" c="dimmed">
        Checking expression…
      </Text>
    )
  else if (valid)
    content = (
      <Group gap={4}>
        <IconCheck size={16} aria-hidden color="var(--mantine-color-green-filled)" />
        <Text size="sm">Expression compiles against environment v1.</Text>
      </Group>
    )
  return (
    <div aria-live="polite" data-testid="policy-validation">
      {content}
    </div>
  )
}

const envFields: [string, string][] = [
  ['principal.id', 'Public user ID (or service account ID)'],
  ['principal.type', 'user or service_account'],
  ['principal.email', 'Primary email address'],
  ['principal.email_domain', 'Domain part of the email'],
  ['principal.groups', 'Slugs of the groups the subject belongs to (including parents)'],
  ['principal.roles', 'Slugs of roles assigned at tenant scope'],
  ['principal.auth_method', 'How the subject signed in'],
  ['principal.auth_age', 'Seconds since the user signed in'],
  ['principal.attributes', 'map of string attributes'],
  ['resource.id / resource.type / resource.slug', 'The target (type tenant, app or a resource type)'],
  ['resource.attributes', 'Attributes of the resource (map)'],
  ['action', 'The permission being checked, e.g. app:access'],
  ['context.ip', 'Client IP address'],
  ['context.network', '"trusted" when the IP is in authz.trusted_networks, else "external"'],
  ['context.tenant', 'Tenant slug'],
  ['context.hour / context.weekday', 'UTC hour (0–23) and weekday ("Mon" … "Sun")'],
  ['now', 'Current time'],
]

const envHelpers: [string, string][] = [
  ['inGroup(principal, "slug")', 'Membership of a group (directly or through nesting)'],
  ['hasAttr(principal | resource, "key")', 'Whether an attribute is set'],
  ['before(now, "2030-01-01T00:00:00Z")', 'Time comparison against an RFC 3339 timestamp'],
  ['cidrMatch(context.ip, "10.0.0.0/8")', 'Whether an IP is inside a CIDR range'],
  ['len, all, any, none, one, filter, map, count', 'Collection built-ins'],
  ['lower, upper, trim, hasPrefix, hasSuffix', 'String built-ins'],
  ['abs, min, max, duration, date', 'Number and time built-ins'],
]

function EnvironmentReference() {
  return (
    <Accordion variant="contained" chevronPosition="left">
      <Accordion.Item value="ref">
        <Accordion.Control>Environment v1 reference</Accordion.Control>
        <Accordion.Panel>
          <Stack gap="sm">
            <Table aria-label="Policy environment fields" withRowBorders>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Field</Table.Th>
                  <Table.Th>Meaning</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {envFields.map(([f, d]) => (
                  <Table.Tr key={f}>
                    <Table.Td>
                      <Code>{f}</Code>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{d}</Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            <Table aria-label="Policy helper functions" withRowBorders>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Helper</Table.Th>
                  <Table.Th>Meaning</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {envHelpers.map(([f, d]) => (
                  <Table.Tr key={f}>
                    <Table.Td>
                      <Code>{f}</Code>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{d}</Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            <Text size="sm" c="dimmed">
              Expressions are sandboxed: at most {MAX_EXPRESSION} characters and 256 nodes, no other functions. A
              condition that fails to evaluate counts as false; a deny policy that fails to evaluate denies.
            </Text>
          </Stack>
        </Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  )
}
