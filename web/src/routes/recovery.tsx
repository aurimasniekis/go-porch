import { Alert, Button, Stack, Text } from '@mantine/core'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { api, ApiError, setCsrfToken, unwrap } from '@/api/client'
import { AuthLayout } from '@/components/AuthLayout'

export const Route = createFileRoute('/recovery')({
  validateSearch: (s: Record<string, unknown>) => ({ token: typeof s.token === 'string' ? s.token : '' }),
  component: function Recovery() {
    const { token } = Route.useSearch()
    const navigate = useNavigate()
    const [error, setError] = useState('')
    const [busy, setBusy] = useState(false)
    // Consumed only on an explicit click, never on page load (link scanners must not burn it).
    const use = async () => {
      setBusy(true)
      setError('')
      try {
        const me = unwrap(await api.POST('/auth/recovery', { body: { token } }))
        setCsrfToken(me.csrf_token)
        await navigate({ to: '/account' })
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Recovery failed')
      } finally {
        setBusy(false)
      }
    }
    return (
      <AuthLayout title="Account recovery">
        <Stack>
          <Text>
            This one-time link was issued by your administrator on the server. Using it is recorded and the
            administrators are alerted.
          </Text>
          {error ? <Alert color="red">{error}</Alert> : null}
          <Button onClick={() => void use()} loading={busy} disabled={!token}>
            Sign in with this link
          </Button>
        </Stack>
      </AuthLayout>
    )
  },
})
