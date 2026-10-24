import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { adminQuery } from '@/api/admin'
import { AutomationTokens } from '@/components/admin/AutomationTokens'

export const Route = createFileRoute('/_app/admin/t/$tenant/tokens')({
  component: function TenantTokens() {
    const { tenant } = Route.useParams()
    const caps = useQuery(adminQuery)
    const t = caps.data?.tenants.find((x) => x.slug === tenant || x.id === tenant)
    return (
      <AutomationTokens
        key={tenant}
        scope={{ kind: 'tenant', tenant, permissions: t?.permissions ?? [] }}
        canManage={!!t}
      />
    )
  },
})
