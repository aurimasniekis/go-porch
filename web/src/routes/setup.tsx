import { Alert, Button, PasswordInput, Stack, TextInput } from '@mantine/core'
import { useForm } from '@mantine/form'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useState } from 'react'
import { api, ApiError, setCsrfToken, unwrap } from '@/api/client'
import { AuthLayout } from '@/components/AuthLayout'

export const Route = createFileRoute('/setup')({
  component: function Setup() {
    const navigate = useNavigate()
    const [error, setError] = useState('')
    const form = useForm({ initialValues: { token: '', display_name: '', email: '' } })
    const submit = form.onSubmit(async (v) => {
      setError('')
      try {
        const me = unwrap(await api.POST('/setup', { body: v }))
        setCsrfToken(me.csrf_token)
        await navigate({ to: '/account' })
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Setup failed')
      }
    })
    return (
      <AuthLayout title="Set up Porch">
        <form onSubmit={submit}>
          <Stack>
            <Alert color="blue">
              Paste the one-time token printed by <code>porch admin setup-token</code> on the server.
            </Alert>
            {error ? <Alert color="red">{error}</Alert> : null}
            <PasswordInput label="Setup token" required autoComplete="off" {...form.getInputProps('token')} />
            <TextInput label="Your name" required autoComplete="name" {...form.getInputProps('display_name')} />
            <TextInput label="Email (optional)" type="email" autoComplete="email" {...form.getInputProps('email')} />
            <Button type="submit" loading={form.submitting}>
              Create owner account
            </Button>
          </Stack>
        </form>
      </AuthLayout>
    )
  },
})
