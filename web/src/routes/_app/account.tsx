import { Alert, Badge, Button, Card, Group, PasswordInput, Stack, Table, Text, TextInput, Title } from '@mantine/core'
import { useForm } from '@mantine/form'
import { notifications } from '@mantine/notifications'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { actionUrl, api, ApiError, check, unwrap } from '@/api/client'
import { backupStatusQuery, identitiesQuery, loginOptionsQuery, myGrantsQuery, mySessionsQuery } from '@/api/queries'
import { UserShell } from '@/components/UserShell'

export const Route = createFileRoute('/_app/account')({
  component: function Account() {
    const { me } = Route.useRouteContext()
    return (
      <UserShell
        me={me}
        title="Account"
        subtitle="How you sign in, where you are signed in, and which apps keep you signed in."
      >
        <Stack maw={880} mx="auto">
          <Identities />
          <BackupCredential />
          <Sessions />
          <Grants />
        </Stack>
      </UserShell>
    )
  },
})

/** Runs an action; a reauth_required problem sends the browser through the step-up flow and back here. */
function stepUpOr(e: unknown, fallback: string): string {
  if (e instanceof ApiError && e.code === 'reauth_required' && e.action) {
    window.location.assign(actionUrl(e.action))
    return ''
  }
  return e instanceof ApiError ? e.message : fallback
}

function Identities() {
  const ids = useQuery(identitiesQuery)
  const opts = useQuery(loginOptionsQuery)
  return (
    <Card>
      <Title order={2} size="h4" mb="sm">
        Linked sign-in accounts
      </Title>
      {ids.data?.length ? (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Provider</Table.Th>
              <Table.Th>Email</Table.Th>
              <Table.Th>Workspace</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {ids.data.map((i) => (
              <Table.Tr key={i.id}>
                <Table.Td>{i.provider_name}</Table.Td>
                <Table.Td>{i.email}</Table.Td>
                <Table.Td>{i.hd ?? '—'}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : (
        <Text c="dimmed">No external accounts linked.</Text>
      )}
      <Group mt="md">
        {opts.data?.providers.map((p) => (
          <Button key={p.slug} variant="light" component="a" href={`${p.login_url}?intent=link&return_to=/account`}>
            Link {p.name} account
          </Button>
        ))}
      </Group>
      <Text size="xs" c="dimmed" mt="xs">
        Linking requires a recent sign-in here, then a sign-in at the provider. Accounts are never linked by email.
      </Text>
    </Card>
  )
}

interface PairInput {
  title: string
  answer: string
  confirm: string
}

function BackupCredential() {
  const qc = useQueryClient()
  const status = useQuery(backupStatusQuery)
  const [editing, setEditing] = useState(false)
  const [error, setError] = useState('')
  const min = status.data?.min_pairs ?? 3
  const max = status.data?.max_pairs ?? 12
  const form = useForm<{ password: string; password2: string; pairs: PairInput[] }>({
    initialValues: {
      password: '',
      password2: '',
      pairs: Array.from({ length: min }, () => ({ title: '', answer: '', confirm: '' })),
    },
    validate: { password2: (v, all) => (v === all.password ? null : 'Passwords do not match') },
  })
  const handleForm = useForm({ initialValues: { handle: '' } })

  const suggest = async (i: number) => {
    const words = unwrap(await api.GET('/me/suggest-words', { params: { query: { count: 3 } } }))
    form.setFieldValue(`pairs.${i}.answer`, words.join(' '))
    form.setFieldValue(`pairs.${i}.confirm`, '')
  }
  const save = form.onSubmit(async (v) => {
    setError('')
    try {
      const est = unwrap(
        await api.PUT('/me/backup-credential', {
          body: {
            password: v.password,
            pairs: v.pairs.map((p) => ({ title: p.title, answer: p.answer })),
            confirm: v.pairs.map((p) => p.confirm),
          },
        }),
      )
      notifications.show({
        color: 'green',
        message: `Backup login saved (≈${Math.round(est.combined_bits_estimate)} bits, estimate)`,
      })
      setEditing(false)
      form.reset()
      await qc.invalidateQueries({ queryKey: ['backup-credential'] })
    } catch (e) {
      setError(stepUpOr(e, 'Could not save'))
    }
  })
  const saveHandle = handleForm.onSubmit(async (v) => {
    try {
      check(await api.PUT('/me/backup-handle', { body: { handle: v.handle } }))
      notifications.show({ color: 'green', message: 'Handle saved' })
      await qc.invalidateQueries({ queryKey: ['backup-credential'] })
    } catch (e) {
      const msg = stepUpOr(e, 'Could not save handle')
      if (msg) notifications.show({ color: 'red', message: msg })
    }
  })

  const s = status.data
  return (
    <Card>
      <Group justify="space-between" mb="sm">
        <Title order={2} size="h4">
          Backup login
        </Title>
        {s?.enrolled ? <Badge variant="default">enrolled</Badge> : <Badge variant="default">not set up</Badge>}
      </Group>
      <Text size="sm" mb="sm">
        For when Google is unavailable: a password plus your own recovery questions, each with a title only you
        understand. One wrong attempt locks the backup login for 6 hours (Google sign-in keeps working).
      </Text>
      {s?.locked_until ? (
        <Alert color="orange" mb="sm">
          Locked until {new Date(s.locked_until).toLocaleString()}.
        </Alert>
      ) : null}
      {s?.enrolled && !editing ? (
        <Stack gap="xs">
          <Text size="sm" fw={500}>
            Your recovery titles
          </Text>
          {s.titles.map((t) => (
            <Text key={t} size="sm">
              • {t}
            </Text>
          ))}
          <Group>
            <Button
              variant="light"
              onClick={() => {
                setEditing(true)
              }}
            >
              Rotate backup login
            </Button>
          </Group>
        </Stack>
      ) : null}
      {!s?.enrolled || editing ? (
        <form onSubmit={save}>
          <Stack>
            {error ? <Alert color="red">{error}</Alert> : null}
            <PasswordInput
              label="Backup password"
              required
              autoComplete="new-password"
              {...form.getInputProps('password')}
            />
            <PasswordInput
              label="Repeat password"
              required
              autoComplete="new-password"
              {...form.getInputProps('password2')}
            />
            {form.values.pairs.map((_, i) => (
              <Card key={i} padding="sm">
                <Stack gap="xs">
                  <TextInput
                    label={`Recovery title ${i + 1}`}
                    description="Your own hint, shown to you at sign-in after the password"
                    required
                    {...form.getInputProps(`pairs.${i}.title`)}
                  />
                  <Group align="end" grow>
                    <TextInput
                      label="Answer"
                      required
                      autoComplete="off"
                      {...form.getInputProps(`pairs.${i}.answer`)}
                    />
                    <Button variant="subtle" onClick={() => void suggest(i)} style={{ flexGrow: 0 }}>
                      Suggest random words
                    </Button>
                  </Group>
                  <TextInput
                    label="Type the answer again"
                    required
                    autoComplete="off"
                    {...form.getInputProps(`pairs.${i}.confirm`)}
                  />
                </Stack>
              </Card>
            ))}
            <Group>
              <Button
                variant="default"
                disabled={form.values.pairs.length >= max}
                onClick={() => {
                  form.insertListItem('pairs', { title: '', answer: '', confirm: '' })
                }}
              >
                Add question
              </Button>
              <Button
                variant="default"
                disabled={form.values.pairs.length <= min}
                onClick={() => {
                  form.removeListItem('pairs', form.values.pairs.length - 1)
                }}
              >
                Remove last
              </Button>
            </Group>
            <Text size="xs" c="dimmed">
              Answers ignore case and punctuation. Avoid answers that can be found online; the strength shown after
              saving is only an estimate.
            </Text>
            <Group>
              <Button type="submit" loading={form.submitting}>
                Save backup login
              </Button>
              {editing ? (
                <Button
                  variant="subtle"
                  onClick={() => {
                    setEditing(false)
                  }}
                >
                  Cancel
                </Button>
              ) : null}
            </Group>
          </Stack>
        </form>
      ) : null}
      <form onSubmit={saveHandle}>
        <Group align="end" mt="lg">
          <TextInput
            label="Backup login handle"
            description={
              s?.handle ? `Current: ${s.handle}` : 'Optional. When set, your email no longer works for backup login.'
            }
            {...handleForm.getInputProps('handle')}
          />
          <Button type="submit" variant="light">
            Save handle
          </Button>
        </Group>
      </form>
    </Card>
  )
}

function Sessions() {
  const qc = useQueryClient()
  const sessions = useQuery(mySessionsQuery)
  const revoke = async (id: string) => {
    check(await api.DELETE('/me/sessions/{session}', { params: { path: { session: id } } }))
    await qc.invalidateQueries({ queryKey: ['my-sessions'] })
  }
  return (
    <Card>
      <Title order={2} size="h4" mb="sm">
        Signed-in browsers
      </Title>
      <Table>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Method</Table.Th>
            <Table.Th>Last active</Table.Th>
            <Table.Th>Address</Table.Th>
            <Table.Th>
              <span className="visually-hidden">Actions</span>
            </Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {sessions.data?.map((s) => (
            <Table.Tr key={s.id}>
              <Table.Td>
                {s.method}
                {s.current ? ' (this browser)' : ''}
              </Table.Td>
              <Table.Td>{new Date(s.last_seen_at).toLocaleString()}</Table.Td>
              <Table.Td>{s.ip}</Table.Td>
              <Table.Td>
                {s.current ? null : (
                  <Button size="xs" variant="subtle" onClick={() => void revoke(s.id)}>
                    Sign out
                  </Button>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Card>
  )
}

function Grants() {
  const qc = useQueryClient()
  const grants = useQuery(myGrantsQuery)
  const revoke = async (family: string) => {
    check(await api.DELETE('/me/grants/{family}', { params: { path: { family } } }))
    await qc.invalidateQueries({ queryKey: ['my-grants'] })
  }
  return (
    <Card>
      <Title order={2} size="h4" mb="sm">
        Applications with offline access
      </Title>
      {grants.data?.length ? (
        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Application</Table.Th>
              <Table.Th>Since</Table.Th>
              <Table.Th>
                <span className="visually-hidden">Actions</span>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {grants.data.map((g) => (
              <Table.Tr key={g.family_id}>
                <Table.Td>{g.app_name}</Table.Td>
                <Table.Td>{new Date(g.created_at).toLocaleString()}</Table.Td>
                <Table.Td>
                  <Button size="xs" variant="subtle" onClick={() => void revoke(g.family_id)}>
                    Revoke
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : (
        <Text c="dimmed">No application keeps you signed in in the background.</Text>
      )}
    </Card>
  )
}
