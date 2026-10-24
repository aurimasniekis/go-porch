import { createFileRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/admin/kit'
import { AuditExplorer } from '@/components/admin/install/AuditExplorer'
import { auditSearch } from '@/components/admin/install/search'

export const Route = createFileRoute('/_app/admin/t/$tenant/audit')({
  validateSearch: auditSearch,
  component: function TenantAudit() {
    const { tenant } = Route.useParams()
    const search = Route.useSearch()
    return (
      <>
        <PageHeader
          title="Audit log"
          description="Actions in this tenant, newest first. Sensitive details are sealed and never shown here."
        />
        <AuditExplorer key={`${tenant}:${JSON.stringify(search)}`} tenant={tenant} initial={search} />
      </>
    )
  },
})
