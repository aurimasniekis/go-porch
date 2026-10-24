import { loginErrorMessage, safeReturnTo } from './redirect'

describe('safeReturnTo', () => {
  it.each(['https://evil.example', '//evil.example', '/\\evil', 'java' + 'script:alert(1)', 'evil', '', '/a\nb'])(
    'rejects %s',
    (s) => {
      expect(safeReturnTo(s)).toBe('/')
    },
  )
  it.each(['/', '/apps', '/account?tab=backup'])('keeps %s', (s) => {
    expect(safeReturnTo(s)).toBe(s)
  })
})

describe('loginErrorMessage', () => {
  it('has a generic fallback', () => {
    expect(loginErrorMessage('???')).toMatch(/Sign-in failed/)
  })
})
