import {
  ActionIcon,
  Button,
  Group,
  Text,
  Title,
  Tooltip,
  useComputedColorScheme,
  useMantineColorScheme,
} from '@mantine/core'
import { IconLogout, IconMoon, IconSettings, IconSun } from '@tabler/icons-react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { adminQuery } from '@/api/admin'
import { api, check, type Me } from '@/api/client'
import { appearanceQuery } from '@/api/queries'
import { backgroundStyle, Credit } from './user/Backdrop'

/** Signs out and returns to the sign-in page. */
export function useLogout() {
  const qc = useQueryClient()
  return async () => {
    check(await api.POST('/logout'))
    qc.clear()
    window.location.assign('/login')
  }
}

/** Light/dark toggle; the stored scheme can be 'auto', so the icon follows the scheme actually shown. */
export function ColorSchemeToggle({ variant = 'subtle', color }: { variant?: string; color?: string }) {
  const { setColorScheme } = useMantineColorScheme()
  const scheme = useComputedColorScheme('light')
  return (
    <Tooltip label="Toggle color scheme">
      <ActionIcon
        variant={variant}
        color={color}
        aria-label="Toggle color scheme"
        onClick={() => {
          setColorScheme(scheme === 'dark' ? 'light' : 'dark')
        }}
      >
        {scheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
      </ActionIcon>
    </Tooltip>
  )
}

/**
 * The user-facing shell (launcher, account): a header band showing the installation's background, the page title and
 * whatever the page puts under it, then the page body.
 */
export function UserShell({
  me,
  title,
  subtitle,
  hero,
  children,
}: {
  me: Me
  title: string
  subtitle?: ReactNode
  hero?: ReactNode
  children: ReactNode
}) {
  const look = useQuery(appearanceQuery)
  const admin = useQuery(adminQuery)
  const logout = useLogout()
  const canAdmin = !!admin.data && (admin.data.auditor || admin.data.tenants.length > 0)
  const brand = look.data?.title ?? 'Porch'
  return (
    <>
      <header className="porch-hero" style={backgroundStyle(look.data?.background)}>
        <div className="porch-hero-inner">
          <nav className="porch-topbar" aria-label="Main">
            <Link to="/" className="porch-brand">
              <img src="/logo.svg" alt="" width={30} height={30} />
              {brand}
            </Link>
            <Group gap={6} wrap="nowrap">
              <Link to="/" className="porch-toplink">
                Applications
              </Link>
              <Link to="/account" className="porch-toplink">
                Account
              </Link>
              {canAdmin ? (
                <Button
                  component={Link}
                  to="/admin"
                  size="xs"
                  variant="white"
                  color="dark"
                  leftSection={<IconSettings size={14} aria-hidden />}
                >
                  Administration
                </Button>
              ) : null}
              <Text size="sm" c="gray.2" visibleFrom="sm" px={6}>
                {me.display_name}
              </Text>
              <ColorSchemeToggle variant="subtle" color="gray.0" />
              <Tooltip label="Sign out">
                <ActionIcon variant="subtle" color="gray.0" aria-label="Sign out" onClick={() => void logout()}>
                  <IconLogout size={18} />
                </ActionIcon>
              </Tooltip>
            </Group>
          </nav>
          <div className="porch-hero-body">
            <Title order={1} size="h2">
              {title}
            </Title>
            {subtitle ? (
              <Text className="porch-hero-sub" mt={6}>
                {subtitle}
              </Text>
            ) : null}
            {hero}
          </div>
        </div>
      </header>
      <main className="porch-main">{children}</main>
      <footer>
        <Credit background={look.data?.background} className="porch-footer-credit" />
      </footer>
    </>
  )
}
