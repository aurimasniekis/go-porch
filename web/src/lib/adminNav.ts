import type { AdminTenant } from '@/api/admin'

/** Administration sections. Visibility follows /me/admin; the server enforces every permission. */
export interface TenantSection {
  slug: string
  label: string
  /** Any of these permissions shows the section (a read permission shows it read-only, ADR-0048). */
  perms: string[]
  /** Installation operators and inspectors only (domain rules are installation-wide). */
  operatorOnly?: boolean
}

export const tenantSections: TenantSection[] = [
  { slug: 'members', label: 'Members', perms: ['member:manage', 'member:read'] },
  { slug: 'invites', label: 'Invitations', perms: ['invite:manage', 'invite:read'] },
  { slug: 'applications', label: 'Applications', perms: ['app:manage', 'app:read'] },
  { slug: 'service-accounts', label: 'Service accounts', perms: ['service_account:manage', 'service_account:read'] },
  { slug: 'groups', label: 'Groups', perms: ['group:manage', 'group:read'] },
  { slug: 'roles', label: 'Roles', perms: ['role:manage', 'role:read'] },
  { slug: 'assignments', label: 'Assignments', perms: ['role:manage', 'role:read'] },
  { slug: 'resources', label: 'Resources', perms: ['resource:manage', 'resource:read'] },
  { slug: 'policies', label: 'Policies', perms: ['policy:manage', 'policy:read'] },
  { slug: 'access', label: 'Access explorer', perms: ['role:manage', 'authz:simulate'] },
  { slug: 'audit', label: 'Audit log', perms: ['audit:read'] },
  { slug: 'domains', label: 'Domain rules', perms: ['tenant:manage'], operatorOnly: true },
  { slug: 'tokens', label: 'Automation tokens', perms: ['tenant:manage'] },
  { slug: 'settings', label: 'Settings', perms: ['tenant:manage', 'tenant:read'] },
]

/** The tenant sections the caller sees for one tenant of /me/admin (none without access). */
export function visibleTenantSections(t: AdminTenant | undefined): TenantSection[] {
  if (!t) return []
  return tenantSections.filter((s) =>
    s.operatorOnly ? t.via === 'operator' || t.via === 'inspector' : s.perms.some((p) => t.permissions.includes(p)),
  )
}

export interface InstallationSection {
  slug: string
  label: string
  /** installation: owner/admin; auditor: owner/admin/auditor. */
  needs: 'installation' | 'auditor'
}

export const installationSections: InstallationSection[] = [
  { slug: 'health', label: 'System health', needs: 'auditor' },
  { slug: 'tenants', label: 'Tenants', needs: 'installation' },
  { slug: 'users', label: 'Users', needs: 'installation' },
  { slug: 'providers', label: 'Identity providers', needs: 'installation' },
  { slug: 'sessions', label: 'Sessions', needs: 'installation' },
  { slug: 'audit', label: 'Audit log', needs: 'auditor' },
  { slug: 'alerts', label: 'Alerts', needs: 'auditor' },
  { slug: 'appearance', label: 'Appearance', needs: 'auditor' },
  { slug: 'backups', label: 'Backups', needs: 'auditor' },
  { slug: 'keys', label: 'Keys', needs: 'auditor' },
  { slug: 'tokens', label: 'Automation tokens', needs: 'auditor' },
  { slug: 'operators', label: 'Operators', needs: 'auditor' },
]
