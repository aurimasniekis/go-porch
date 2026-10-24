import { createFileRoute } from '@tanstack/react-router'
import { PageHeader } from '@/components/admin/kit'
import { AuditExplorer } from '@/components/admin/install/AuditExplorer'
import { auditSearch } from '@/components/admin/install/search'

export const Route = createFileRoute('/_app/admin/i/audit')({
  validateSearch: auditSearch,
  component: function InstallationAudit() {
    const search = Route.useSearch()
    return (
      <>
        <PageHeader
          title="Audit log"
          description="Every security-relevant action across the installation, newest first. Events are hash-chained; sensitive details are sealed and never shown here."
        />
        <AuditExplorer key={JSON.stringify(search)} initial={search} />
      </>
    )
  },
})
