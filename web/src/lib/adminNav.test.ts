import type { AdminTenant } from '@/api/admin'
import { canRead, readsInstallationConfig } from '@/api/admin'
import { visibleTenantSections } from './adminNav'

const reads = [
  'app:read',
  'tenant:read',
  'member:read',
  'group:read',
  'role:read',
  'policy:read',
  'resource:read',
  'invite:read',
  'service_account:read',
]
const tenant = (via: AdminTenant['via'], permissions: string[]): AdminTenant => ({
  id: 't1',
  slug: 'smith',
  name: 'Smith',
  via,
  permissions,
})
const slugs = (t: AdminTenant | undefined) => visibleTenantSections(t).map((s) => s.slug)

describe('visibleTenantSections', () => {
  it('shows nothing without a tenant', () => {
    expect(slugs(undefined)).toEqual([])
  })

  it('shows an inspector every configuration section, domain rules included, but no audit, explorer or tokens', () => {
    expect(slugs(tenant('inspector', reads))).toEqual([
      'members',
      'invites',
      'applications',
      'service-accounts',
      'groups',
      'roles',
      'assignments',
      'resources',
      'policies',
      'domains',
      'settings',
    ])
  })

  it('shows a section for its read permission alone', () => {
    expect(slugs(tenant('delegated', ['app:read']))).toEqual(['applications'])
    expect(slugs(tenant('delegated', ['role:read']))).toEqual(['roles', 'assignments'])
    expect(slugs(tenant('delegated', ['tenant:read']))).toEqual(['settings'])
  })

  it('keeps domain rules from delegated administrators, even with tenant:manage', () => {
    expect(slugs(tenant('delegated', ['tenant:manage']))).toEqual(['tokens', 'settings'])
  })
})

describe('canRead', () => {
  it('accepts the read or the manage permission', () => {
    expect(canRead(tenant('delegated', ['app:read']), 'app')).toBe(true)
    expect(canRead(tenant('delegated', ['app:manage']), 'app')).toBe(true)
    expect(canRead(tenant('delegated', ['group:read']), 'app')).toBe(false)
    expect(canRead(undefined, 'app')).toBe(false)
  })
})

describe('readsInstallationConfig', () => {
  it('is for operators and inspectors only', () => {
    expect(readsInstallationConfig(tenant('operator', []))).toBe(true)
    expect(readsInstallationConfig(tenant('inspector', reads))).toBe(true)
    expect(readsInstallationConfig(tenant('delegated', ['tenant:manage']))).toBe(false)
  })
})
