import { Box, Divider, Flex, NavLink, ScrollArea, Select, Stack, Text } from '@mantine/core'
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, Link, Outlet, useNavigate, useParams, useRouterState } from '@tanstack/react-router'
import { adminQuery, type AdminCapabilities } from '@/api/admin'
import { ErrorAlert } from '@/components/admin/kit'
import { installationSections, tenantSections } from '@/lib/adminNav'

export const Route = createFileRoute('/_app/admin')({
  loader: ({ context }) => context.queryClient.query(adminQuery),
  component: AdminLayout,
})

function visibleTenantSections(caps: AdminCapabilities, tenant: string | undefined) {
  const t = caps.tenants.find((x) => x.slug === tenant || x.id === tenant)
  if (!t) return []
  return tenantSections.filter((s) =>
    s.operatorOnly ? t.via === 'operator' : s.perms.some((p) => t.permissions.includes(p)),
  )
}

function AdminLayout() {
  const caps = useQuery(adminQuery)
  const params = useParams({ strict: false })
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const navigate = useNavigate()
  if (caps.error) return <ErrorAlert error={caps.error} />
  if (!caps.data) return null
  const c = caps.data
  const tenant = params.tenant
  const section = pathname.split('/')[4] ?? ''
  const install = installationSections.filter((s) => (s.needs === 'installation' ? c.installation : c.auditor))
  return (
    <Flex direction={{ base: 'column', md: 'row' }} gap="lg" maw={1400} mx="auto">
      <Box component="nav" aria-label="Administration" w={{ base: '100%', md: 240 }} style={{ flexShrink: 0 }}>
        <ScrollArea.Autosize mah={{ md: 'calc(100vh - 100px)' }}>
          <Stack gap={4}>
            {c.tenants.length > 0 ? (
              <>
                <Select
                  label="Tenant"
                  placeholder="Choose a tenant"
                  data={c.tenants.map((t) => ({ value: t.slug, label: t.name }))}
                  value={tenant ?? null}
                  searchable
                  allowDeselect={false}
                  onChange={(v) => {
                    if (!v) return
                    const sections = visibleTenantSections(c, v)
                    const next = sections.find((s) => s.slug === section) ?? sections.at(0)
                    if (next) void navigate({ to: `/admin/t/${v}/${next.slug}` })
                  }}
                  mb="xs"
                />
                {visibleTenantSections(c, tenant).map((s) => (
                  <NavLink
                    key={s.slug}
                    component={Link}
                    to={`/admin/t/${tenant ?? ''}/${s.slug}`}
                    label={s.label}
                    active={pathname.startsWith(`/admin/t/${tenant ?? ''}/${s.slug}`)}
                  />
                ))}
              </>
            ) : null}
            {install.length > 0 ? (
              <>
                {c.tenants.length > 0 ? <Divider my="sm" /> : null}
                <Text size="xs" fw={700} c="dimmed" tt="uppercase" px="sm">
                  Installation
                </Text>
                {install.map((s) => (
                  <NavLink
                    key={s.slug}
                    component={Link}
                    to={`/admin/i/${s.slug}`}
                    label={s.label}
                    active={pathname.startsWith(`/admin/i/${s.slug}`)}
                  />
                ))}
              </>
            ) : null}
          </Stack>
        </ScrollArea.Autosize>
      </Box>
      <Box component="section" style={{ flex: 1, minWidth: 0 }}>
        <Outlet />
      </Box>
    </Flex>
  )
}
