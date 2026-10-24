import {
  ActionIcon,
  AppShell,
  Anchor,
  Group,
  Text,
  Tooltip,
  useComputedColorScheme,
  useMantineColorScheme,
} from '@mantine/core'
import { IconLogout, IconMoon, IconSun } from '@tabler/icons-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { adminQuery } from '@/api/admin'
import { api, check, type Me } from '@/api/client'

export function AppLayout({ me, children }: { me: Me; children: ReactNode }) {
  const qc = useQueryClient()
  const admin = useQuery(adminQuery)
  // The stored scheme can be 'auto'; the icon and the toggle follow the scheme actually shown.
  const { setColorScheme } = useMantineColorScheme()
  const colorScheme = useComputedColorScheme('light')
  const toggleColorScheme = () => {
    setColorScheme(colorScheme === 'dark' ? 'light' : 'dark')
  }
  const logout = async () => {
    check(await api.POST('/logout'))
    qc.clear()
    window.location.assign('/login')
  }
  return (
    <AppShell header={{ height: 52 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="lg">
            <Anchor component={Link} to="/" fw={700} underline="never">
              <Group gap={8} wrap="nowrap">
                <img src="/logo.svg" alt="" width={22} height={22} />
                Porch
              </Group>
            </Anchor>
            <Anchor component={Link} to="/account" size="sm">
              Account
            </Anchor>
            {admin.data && (admin.data.auditor || admin.data.tenants.length > 0) ? (
              <Anchor component={Link} to="/admin" size="sm">
                Administration
              </Anchor>
            ) : null}
          </Group>
          <Group gap="xs">
            <Text size="sm" c="dimmed">
              {me.display_name}
            </Text>
            <Tooltip label="Toggle color scheme">
              <ActionIcon variant="subtle" aria-label="Toggle color scheme" onClick={toggleColorScheme}>
                {colorScheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
              </ActionIcon>
            </Tooltip>
            <Tooltip label="Sign out">
              <ActionIcon variant="subtle" aria-label="Sign out" onClick={() => void logout()}>
                <IconLogout size={18} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>
      </AppShell.Header>
      <AppShell.Main>{children}</AppShell.Main>
    </AppShell>
  )
}
