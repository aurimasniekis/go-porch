import { useQuery } from '@tanstack/react-query'
import { createFileRoute } from '@tanstack/react-router'
import { adminQuery } from '@/api/admin'
import { AutomationTokens } from '@/components/admin/AutomationTokens'

export const Route = createFileRoute('/_app/admin/i/tokens')({
  component: function InstallationTokens() {
    const caps = useQuery(adminQuery)
    return (
      <AutomationTokens
        scope={{ kind: 'installation' }}
        canManage={caps.data?.operator_roles.includes('owner') ?? false}
      />
    )
  },
})
