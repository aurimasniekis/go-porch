import { Paper, Stack, Text, Title } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { appearanceQuery } from '@/api/queries'
import { Backdrop, Credit } from './user/Backdrop'

/**
 * Sign-in, setup and recovery pages: the installation's background behind a centred card with the logo. `title` is the
 * card heading; it defaults to "Welcome to <installation title>".
 */
export function AuthLayout({
  title,
  subtitle,
  children,
}: {
  title?: string
  subtitle?: ReactNode
  children: ReactNode
}) {
  const look = useQuery(appearanceQuery)
  const name = look.data?.title ?? 'Porch'
  return (
    <>
      <Backdrop background={look.data?.background} />
      <main className="porch-auth">
        <Paper className="porch-auth-card" p={36} radius="lg">
          <Stack gap="lg">
            <Stack gap={10} align="center">
              <img className="porch-logo" src="/logo.svg" alt="" width={56} height={56} />
              <Title order={1} size="h3" ta="center">
                {title ?? `Welcome to ${name}`}
              </Title>
              {subtitle ? (
                <Text size="sm" c="dimmed" ta="center">
                  {subtitle}
                </Text>
              ) : null}
            </Stack>
            {children}
          </Stack>
        </Paper>
      </main>
      <Credit background={look.data?.background} />
    </>
  )
}
