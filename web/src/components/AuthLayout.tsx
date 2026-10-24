import { Center, Paper, Stack, Title } from '@mantine/core'
import type { ReactNode } from 'react'

export function AuthLayout({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Center mih="100vh" p="md">
      <Paper withBorder shadow="sm" p="xl" w={440} maw="100%" radius="md">
        <Stack gap="md">
          <Title order={1} size="h2">
            {title}
          </Title>
          {children}
        </Stack>
      </Paper>
    </Center>
  )
}
