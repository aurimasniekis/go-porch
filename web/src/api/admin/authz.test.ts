import { ApiError } from '../client'
import {
  CONFLICT_MESSAGE,
  conflictAware,
  isEscalation,
  memberLabel,
  missingPermissions,
  normalizeDecision,
  type Decision,
  type Member,
} from './authz'

describe('authz admin API helpers', () => {
  it('normalises null trace lists from the server', () => {
    const raw = {
      allowed: false,
      reason: 'tenant_gate',
      trace: {
        tenant_gate: { passed: false, via: 'none' },
        groups: null,
        candidates: null,
        deny_policies: null,
        context: {},
        simulated: false,
        epoch: 0,
      },
    } as unknown as Decision
    const d = normalizeDecision(raw)
    expect(d.trace.groups).toEqual([])
    expect(d.trace.candidates).toEqual([])
    expect(d.trace.deny_policies).toEqual([])
    expect(d.reason).toBe('tenant_gate')
  })

  it('reads the missing permissions of an escalation refusal', () => {
    const e = new ApiError(
      {
        detail: 'you cannot grant permissions you do not hold: *:*, doc:read',
        code: 'privilege_escalation',
        fields: [{ field: 'permissions', message: 'not held: *:*, doc:read' }],
      },
      403,
    )
    expect(isEscalation(e)).toBe(true)
    expect(missingPermissions(e)).toEqual(['*:*', 'doc:read'])
    const noFields = new ApiError(
      { detail: 'you cannot grant permissions you do not hold: app:manage', code: 'privilege_escalation' },
      403,
    )
    expect(missingPermissions(noFields)).toEqual(['app:manage'])
    expect(isEscalation(new ApiError({ code: 'forbidden' }, 403))).toBe(false)
  })

  it('turns a stale If-Match into a reload message', async () => {
    await expect(
      conflictAware(Promise.reject(new ApiError({ detail: 'x', code: 'precondition' }, 412))),
    ).rejects.toThrow(CONFLICT_MESSAGE)
    await expect(conflictAware(Promise.reject(new ApiError({ detail: 'nope' }, 400)))).rejects.toThrow('nope')
    await expect(conflictAware(Promise.resolve(1))).resolves.toBe(1)
  })

  it('labels members', () => {
    const m = { user_id: 'u1', display_name: 'Ada', email: 'ada@x' } as Member
    expect(memberLabel(m)).toBe('Ada (ada@x)')
    expect(memberLabel({ user_id: 'u2' } as Member)).toBe('u2')
  })
})
