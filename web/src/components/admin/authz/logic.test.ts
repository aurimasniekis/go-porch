import {
  attributesToRows,
  descendantIds,
  describeReason,
  flattenTree,
  groupDescendants,
  localInputToISO,
  partitionPermissions,
  rowsToAttributes,
  scopeText,
  slugify,
  toLocalInput,
  validAction,
  validAttributeKey,
  validPermission,
  validResourceType,
  validSlug,
} from './logic'

describe('permission validation (mirrors the server regex)', () => {
  it.each([
    ['app:access', true],
    ['doc:read', true],
    ['*:*', true],
    ['app:*', true],
    ['*:read', true],
    ['service_account:manage', true],
    ['App:access', false],
    ['app', false],
    ['app:', false],
    [':read', false],
    ['1app:read', false],
    ['app:read:x', false],
    ['a'.repeat(32) + ':x', true],
    ['a'.repeat(33) + ':x', false],
    ['doc-x:read', false],
  ])('%s → %s', (p, ok) => {
    expect(validPermission(p)).toBe(ok)
  })

  it('partitions entered values and accepts * only when allowed', () => {
    expect(partitionPermissions([' doc:read ', 'bad', 'doc:read', '*'])).toEqual({
      valid: ['doc:read'],
      invalid: ['bad', '*'],
    })
    expect(partitionPermissions(['*', 'app:access'], true)).toEqual({ valid: ['*', 'app:access'], invalid: [] })
  })

  it('actions for checks have no wildcards', () => {
    expect(validAction('app:access')).toBe(true)
    expect(validAction('app:*')).toBe(false)
  })
})

describe('slugs, types and attribute keys', () => {
  it('validates slugs like the server', () => {
    expect(validSlug('team-a')).toBe(true)
    expect(validSlug('a')).toBe(true)
    expect(validSlug('-a')).toBe(false)
    expect(validSlug('a-')).toBe(false)
    expect(validSlug('A')).toBe(false)
    expect(validSlug('a'.repeat(64))).toBe(false)
  })
  it('validates resource types', () => {
    expect(validResourceType('doc')).toBe(true)
    expect(validResourceType('project_x')).toBe(true)
    expect(validResourceType('*')).toBe(false)
    expect(validResourceType('')).toBe(false)
    expect(validResourceType('doc-x')).toBe(false)
  })
  it('accepts slug or identifier attribute keys', () => {
    expect(validAttributeKey('cost-center')).toBe(true)
    expect(validAttributeKey('cost_center')).toBe(true)
    expect(validAttributeKey('Cost')).toBe(false)
    expect(validAttributeKey('')).toBe(false)
  })
  it('suggests slugs from names', () => {
    expect(slugify('  Žemaitė Team!  ')).toBe('zemaite-team')
    expect(slugify('A'.repeat(70))).toHaveLength(63)
  })
})

describe('trees', () => {
  const items = [
    { id: 'c', parent_id: 'b', n: 'c' },
    { id: 'a', n: 'a' },
    { id: 'b', parent_id: 'a', n: 'b' },
    { id: 'd', parent_id: 'missing', n: 'd' },
    { id: 'b2', parent_id: 'a', n: 'b2' },
  ]
  it('flattens depth-first with depths and descendant counts', () => {
    const flat = flattenTree(items, (x, y) => x.n.localeCompare(y.n))
    expect(flat.map((f) => [f.item.id, f.depth, f.descendants])).toEqual([
      ['a', 0, 3],
      ['b', 1, 1],
      ['c', 2, 0],
      ['b2', 1, 0],
      ['d', 0, 0],
    ])
  })
  it('cuts cycles but shows every item once', () => {
    const flat = flattenTree([
      { id: 'x', parent_id: 'y' },
      { id: 'y', parent_id: 'x' },
    ])
    expect(flat.map((f) => f.item.id).sort()).toEqual(['x', 'y'])
  })
  it('finds descendants', () => {
    expect([...descendantIds(items, 'a')].sort()).toEqual(['b', 'b2', 'c'])
    expect(descendantIds(items, 'c').size).toBe(0)
  })
  it('finds nested groups below a group', () => {
    const groups = [
      { id: 'p', parents: [] },
      { id: 'c1', parents: ['p'] },
      { id: 'c2', parents: ['c1'] },
      { id: 'x', parents: [] },
    ]
    expect([...groupDescendants(groups, 'p')].sort()).toEqual(['c1', 'c2'])
  })
})

describe('attributes', () => {
  it('converts rows and reports problems', () => {
    expect(
      rowsToAttributes([
        { key: 'tier', value: 'gold' },
        { key: '', value: '' },
      ]),
    ).toEqual({
      attributes: { tier: 'gold' },
    })
    expect(rowsToAttributes([{ key: 'Bad', value: 'x' }]).error).toMatch(/not a valid attribute key/)
    expect(
      rowsToAttributes([
        { key: 'a', value: '1' },
        { key: 'a', value: '2' },
      ]).error,
    ).toMatch(/twice/)
    expect(attributesToRows({ b: '2', a: '1' })).toEqual([
      { key: 'a', value: '1' },
      { key: 'b', value: '2' },
    ])
  })
})

describe('dates and labels', () => {
  it('round-trips datetime-local values', () => {
    const d = new Date(2030, 0, 2, 3, 4)
    const local = toLocalInput(d)
    expect(local).toBe('2030-01-02T03:04')
    expect(localInputToISO(local)).toBe(d.toISOString())
    expect(localInputToISO('')).toBeUndefined()
    expect(localInputToISO('nonsense')).toBeUndefined()
  })
  it('describes reasons and scopes', () => {
    expect(describeReason('granted')).toMatch(/grant applies/)
    expect(describeReason('other')).toBe('other')
    expect(scopeText('tenant', undefined, undefined)).toBe('Whole tenant')
    expect(scopeText('resource_type', 'doc', undefined)).toBe('All doc resources')
    expect(scopeText('resource', 'app', 'Demo app')).toBe('Application: Demo app')
    expect(scopeText('resource', 'doc', 'Handbook')).toBe('doc: Handbook')
  })
})
