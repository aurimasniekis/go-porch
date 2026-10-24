/** Administration sections. Visibility follows /me/admin; the server enforces every permission. */
export interface TenantSection {
  slug: string
  label: string
  /** Any of these permissions shows the section. */
  perms: string[]
  /** Installation operators only (domain rules are installation-wide). */
  operatorOnly?: boolean
}

export const tenantSections: TenantSection[] = [
  { slug: 'members', label: 'Members', perms: ['member:manage'] },
  { slug: 'invites', label: 'Invitations', perms: ['invite:manage'] },
  { slug: 'applications', label: 'Applications', perms: ['app:manage'] },
  { slug: 'service-accounts', label: 'Service accounts', perms: ['service_account:manage'] },
  { slug: 'groups', label: 'Groups', perms: ['group:manage'] },
  { slug: 'roles', label: 'Roles', perms: ['role:manage'] },
  { slug: 'assignments', label: 'Assignments', perms: ['role:manage'] },
  { slug: 'resources', label: 'Resources', perms: ['resource:manage'] },
  { slug: 'policies', label: 'Policies', perms: ['policy:manage'] },
  { slug: 'access', label: 'Access explorer', perms: ['role:manage', 'authz:simulate'] },
  { slug: 'audit', label: 'Audit log', perms: ['audit:read'] },
  { slug: 'domains', label: 'Domain rules', perms: ['tenant:manage'], operatorOnly: true },
  { slug: 'tokens', label: 'Automation tokens', perms: ['tenant:manage'] },
  { slug: 'settings', label: 'Settings', perms: ['tenant:manage'] },
]

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
