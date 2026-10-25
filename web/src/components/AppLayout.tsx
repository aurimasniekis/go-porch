import { ActionIcon, AppShell, Anchor, Burger, Group, ScrollArea, Text, Tooltip } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconLogout } from '@tabler/icons-react'
import { useQuery } from '@tanstack/react-query'
import { Link, useRouterState } from '@tanstack/react-router'
import { useEffect, type ReactNode } from 'react'
import { adminQuery } from '@/api/admin'
import type { Me } from '@/api/client'
import { ColorSchemeToggle, useLogout } from './UserShell'

/**
 * The administration shell: a header and, when `nav` is given, a side navigation that becomes a drawer (opened from
 * the header's menu button) below the `md` breakpoint.
 */
export function AppLayout({ me, nav, children }: { me: Me; nav?: ReactNode; children: ReactNode }) {
  const admin = useQuery(adminQuery)
  const logout = useLogout()
  const [opened, { toggle, close }] = useDisclosure(false)
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  // Choosing a page (or a tenant) in the drawer closes it.
  useEffect(() => {
    close()
  }, [pathname, close])
  const canAdmin = !!admin.data && (admin.data.auditor || admin.data.tenants.length > 0)
  return (
    <AppShell
      header={{ height: 56 }}
      navbar={nav ? { width: 260, breakpoint: 'md', collapsed: { mobile: !opened } } : undefined}
      padding="md"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="lg" wrap="nowrap">
            {nav ? (
              <Burger
                opened={opened}
                onClick={toggle}
                hiddenFrom="md"
                size="sm"
                aria-label="Navigation"
                aria-expanded={opened}
                aria-controls="porch-admin-nav"
              />
            ) : null}
            <Anchor component={Link} to="/" fw={700} underline="never">
              <Group gap={8} wrap="nowrap">
                <img src="/logo.svg" alt="" width={22} height={22} />
                Porch
              </Group>
            </Anchor>
            <Group gap="lg" wrap="nowrap" visibleFrom="sm">
              <Anchor component={Link} to="/account" size="sm">
                Account
              </Anchor>
              {canAdmin ? (
                <Anchor component={Link} to="/admin" size="sm">
                  Administration
                </Anchor>
              ) : null}
            </Group>
          </Group>
          <Group gap="xs" wrap="nowrap">
            <Text size="sm" c="dimmed" visibleFrom="sm" truncate maw={220}>
              {me.display_name}
            </Text>
            <ColorSchemeToggle />
            <Tooltip label="Sign out">
              <ActionIcon variant="subtle" aria-label="Sign out" onClick={() => void logout()}>
                <IconLogout size={18} />
              </ActionIcon>
            </Tooltip>
          </Group>
        </Group>
      </AppShell.Header>
      {nav ? (
        <AppShell.Navbar id="porch-admin-nav" className="porch-drawer-nav" mod={{ open: opened }}>
          <AppShell.Section grow component={ScrollArea} p="sm">
            {nav}
          </AppShell.Section>
          <AppShell.Section hiddenFrom="sm" p="sm" style={{ borderTop: '1px solid var(--app-shell-border-color)' }}>
            <Group justify="space-between" wrap="nowrap">
              <Text size="sm" c="dimmed" truncate>
                {me.display_name}
              </Text>
              <Group gap="md" wrap="nowrap">
                <Anchor component={Link} to="/" size="sm">
                  Applications
                </Anchor>
                <Anchor component={Link} to="/account" size="sm">
                  Account
                </Anchor>
              </Group>
            </Group>
          </AppShell.Section>
        </AppShell.Navbar>
      ) : null}
      <AppShell.Main>{children}</AppShell.Main>
    </AppShell>
  )
}
