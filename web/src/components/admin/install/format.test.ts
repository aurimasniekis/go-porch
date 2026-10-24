import { actorLabel, detailsJson, formatBytes, formatDuration, localInputToIso, targetLabel } from './format'

describe('formatBytes', () => {
  it('uses binary units', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1024)).toBe('1.0 KiB')
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MiB')
    expect(formatBytes(150 * 1024 * 1024)).toBe('150 MiB')
    expect(formatBytes(3 * 1024 ** 4)).toBe('3.0 TiB')
    expect(formatBytes(2048 * 1024 ** 4)).toBe('2048 TiB')
  })
  it('rejects invalid input', () => {
    expect(formatBytes(-1)).toBe('—')
    expect(formatBytes(Number.NaN)).toBe('—')
  })
})

describe('formatDuration', () => {
  it('shows the two largest non-zero units', () => {
    expect(formatDuration(0)).toBe('0 s')
    expect(formatDuration(5_000)).toBe('5 s')
    expect(formatDuration(65_000)).toBe('1 min 5 s')
    expect(formatDuration(3_600_000)).toBe('1 h')
    expect(formatDuration((3 * 86400 + 4 * 3600 + 7) * 1000)).toBe('3 d 4 h')
    expect(formatDuration((86400 + 30) * 1000)).toBe('1 d')
  })
  it('rejects negative durations', () => {
    expect(formatDuration(-1)).toBe('—')
  })
})

describe('localInputToIso', () => {
  it('converts local datetime input to UTC ISO', () => {
    const iso = localInputToIso('2026-10-24T12:30')
    expect(iso).toBe(new Date(2026, 9, 24, 12, 30).toISOString())
  })
  it('returns empty for empty or invalid input', () => {
    expect(localInputToIso('')).toBe('')
    expect(localInputToIso('not a date')).toBe('')
  })
})

describe('audit labels', () => {
  it('prefers the actor name', () => {
    expect(actorLabel({ actor_type: 'user', actor_id: 'usr_1', actor_name: 'Olga' })).toBe('Olga')
    expect(actorLabel({ actor_type: 'user', actor_id: 'usr_1' })).toBe('user:usr_1')
    expect(actorLabel({ actor_type: 'system' })).toBe('system')
  })
  it('formats targets', () => {
    expect(targetLabel({})).toBe('—')
    expect(targetLabel({ target_type: 'tenant', target_id: 'ten_1' })).toBe('tenant:ten_1')
    expect(targetLabel({ target_type: 'installation' })).toBe('installation')
    expect(targetLabel({ target_id: 'x' })).toBe('x')
  })
  it('renders details as JSON text', () => {
    expect(detailsJson(undefined)).toBe('{}')
    expect(detailsJson({ a: '<b>' })).toBe('{\n  "a": "<b>"\n}')
  })
})
