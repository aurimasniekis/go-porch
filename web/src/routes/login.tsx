import { Alert, Anchor, Button, Divider, PasswordInput, Stack, Text, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { IconBrandGoogleFilled, IconCircleX, IconKey } from '@tabler/icons-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { createFileRoute, Link, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { api, ApiError, setCsrfToken, unwrap } from '@/api/client'
import { loginOptionsQuery } from '@/api/queries'
import { AuthLayout } from '@/components/AuthLayout'
import { loginErrorMessage, safeReturnTo } from '@/lib/redirect'

interface Search {
  return_to: string
  error: string
  stepup: string
}

export const Route = createFileRoute('/login')({
  validateSearch: (s: Record<string, unknown>): Search => ({
    return_to: typeof s.return_to === 'string' ? s.return_to : '',
    error: typeof s.error === 'string' ? s.error : '',
    stepup: typeof s.stepup === 'string' ? s.stepup : '',
  }),
  component: Login,
})

function Login() {
  const search = Route.useSearch()
  const navigate = useNavigate()
  const returnTo = safeReturnTo(search.return_to)
  const opts = useQuery(loginOptionsQuery)
  const stepUp = search.stepup === 'backup'
  if (search.error) {
    // Like a denied flow: say what happened and offer one way back.
    return (
      <AuthLayout title="Sign-in not completed">
        <Stack align="center" gap="sm" role="alert">
          <IconCircleX size={56} stroke={1.5} aria-hidden className="porch-denied-icon" />
          <Text ta="center" fw={500}>
            {loginErrorMessage(search.error)}
          </Text>
        </Stack>
        <Button
          variant="default"
          onClick={() =>
            void navigate({ to: '/login', search: { return_to: search.return_to, error: '', stepup: search.stepup } })
          }
        >
          Back to sign in
        </Button>
      </AuthLayout>
    )
  }
  return (
    <AuthLayout
      title={stepUp ? 'Confirm it is you' : undefined}
      subtitle={stepUp ? 'Sign in with your backup login to continue.' : 'Sign in to open your applications.'}
    >
      {opts.data && !opts.data.setup_complete ? (
        <Alert color="blue">
          Porch is not set up yet.{' '}
          <Anchor component={Link} to="/setup">
            Run first-time setup
          </Anchor>
          .
        </Alert>
      ) : null}
      {!stepUp && (opts.data?.providers.length ?? 0) > 0 ? (
        <Stack gap="xs">
          {opts.data?.providers.map((p) => (
            <Button
              key={p.slug}
              component="a"
              size="md"
              href={`${p.login_url}?return_to=${encodeURIComponent(returnTo)}`}
              variant="default"
              leftSection={p.kind === 'google' ? <IconBrandGoogleFilled size={18} /> : <IconKey size={18} />}
            >
              Continue with {p.name}
            </Button>
          ))}
        </Stack>
      ) : null}
      {opts.data?.backup_enabled ? (
        <>
          {!stepUp && opts.data.providers.length > 0 ? (
            <Divider label="or use your backup login" labelPosition="center" />
          ) : null}
          <BackupLogin returnTo={returnTo} />
        </>
      ) : null}
    </AuthLayout>
  )
}

function BackupLogin({ returnTo }: { returnTo: string }) {
  const qc = useQueryClient()
  const [titles, setTitles] = useState<string[] | null>(null)
  const [error, setError] = useState('')
  const step1 = useForm({ initialValues: { identifier: '', password: '' } })
  const step2 = useForm<{ answers: string[] }>({ initialValues: { answers: [] } })

  const start = step1.onSubmit(async (v) => {
    setError('')
    try {
      const ch = unwrap(await api.POST('/auth/backup/start', { body: v }))
      step2.setValues({ answers: ch.titles.map(() => '') })
      setTitles(ch.titles)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Sign-in failed')
    }
  })
  const finish = step2.onSubmit(async (v) => {
    setError('')
    try {
      const me = unwrap(await api.POST('/auth/backup/finish', { body: { answers: v.answers } }))
      setCsrfToken(me.csrf_token)
      qc.clear()
      window.location.assign(returnTo)
    } catch (e) {
      setTitles(null)
      step1.setFieldValue('password', '')
      setError(e instanceof ApiError ? e.message : 'Sign-in failed')
    }
  })

  return (
    <Stack>
      {error ? <Alert color="red">{error}</Alert> : null}
      {titles === null ? (
        <form onSubmit={start}>
          <Stack>
            <TextInput
              label="Backup handle or email"
              required
              autoComplete="username"
              {...step1.getInputProps('identifier')}
            />
            <PasswordInput
              label="Password"
              required
              autoComplete="current-password"
              {...step1.getInputProps('password')}
            />
            <Text size="xs" c="dimmed">
              Backup login locks after a failed attempt. Your Google sign-in is not affected by a lock.
            </Text>
            <Button type="submit" size="md" loading={step1.submitting}>
              Continue
            </Button>
          </Stack>
        </form>
      ) : (
        <form onSubmit={finish}>
          <Stack>
            <Text size="sm">Answer your recovery questions.</Text>
            {titles.map((t, i) => (
              <TextInput key={t} label={t} required autoComplete="off" {...step2.getInputProps(`answers.${i}`)} />
            ))}
            <Button type="submit" loading={step2.submitting}>
              Sign in
            </Button>
          </Stack>
        </form>
      )}
    </Stack>
  )
}
