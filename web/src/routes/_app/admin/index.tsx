import { Card, SimpleGrid, Stack, Text } from '@mantine/core'
import { createFileRoute, Link, redirect } from '@tanstack/react-router'
import { adminQuery } from '@/api/admin'
import { PageHeader } from '@/components/admin/kit'
import { visibleTenantSections } from '@/lib/adminNav'

export const Route = createFileRoute('/_app/admin/')({
  beforeLoad: async ({ context }) => {
    const caps = await context.queryClient.query(adminQuery)
    if (caps.auditor) throw redirect({ to: '/admin/i/health' })
    const t = caps.tenants.at(0)
    const first = visibleTenantSections(t).at(0)
    if (t && first)
      throw redirect({ to: `/admin/t/$tenant/${first.slug}` as '/admin/t/$tenant/members', params: { tenant: t.slug } })
  },
  component: function NoAdmin() {
    return (
      <Stack maw={720}>
        <PageHeader title="Administration" description="You do not administer any tenant on this installation." />
        <SimpleGrid cols={1}>
          <Card>
            <Text>
              Ask a tenant administrator to grant you a role, or go back to <Link to="/">your applications</Link>.
            </Text>
          </Card>
        </SimpleGrid>
      </Stack>
    )
  },
})
