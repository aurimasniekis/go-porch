import { lines, seconds } from '@/api/admin/tenant'
import { headerMap, toClientConfig, toClientForm } from './appForms'
import { curlExample } from './ServiceAccountForms'

describe('lines', () => {
  it('trims and drops blank lines', () => {
    expect(lines(' https://a.example/cb \n\n https://b.example/cb\n')).toEqual([
      'https://a.example/cb',
      'https://b.example/cb',
    ])
  })
})

describe('seconds', () => {
  it.each([
    [600, '10 min'],
    [3600, '1 h'],
    [86400, '1 d'],
    [90, '90 s'],
  ])('%d → %s', (n, s) => {
    expect(seconds(n)).toBe(s)
  })
})

describe('toClientConfig', () => {
  it('sends client and application type only on create, omits default TTLs', () => {
    const f = { ...toClientForm(), redirect_uris: 'https://app.example/cb' }
    const create = toClientConfig(f, true)
    expect(create.client_type).toBe('confidential')
    expect(create.redirect_uris).toEqual(['https://app.example/cb'])
    expect(create.access_token_ttl_seconds).toBeUndefined()
    const edit = toClientConfig({ ...f, access_token_ttl_seconds: 300 }, false)
    expect(edit.client_type).toBeUndefined()
    expect(edit.application_type).toBeUndefined()
    expect(edit.access_token_ttl_seconds).toBe(300)
  })

  it('always requires PKCE for public clients', () => {
    const f = { ...toClientForm(), client_type: 'public' as const, require_pkce: false }
    expect(toClientConfig(f, true).require_pkce).toBe(true)
  })
})

describe('headerMap', () => {
  it('drops rows without a header name', () => {
    expect(
      headerMap([
        { name: ' X-User ', claim: 'sub' },
        { name: '', claim: 'email' },
      ]),
    ).toEqual({ 'X-User': 'sub' })
  })
})

describe('curlExample', () => {
  it('uses the token endpoint and keeps the secret out of the command', () => {
    const s = curlExample('https://id.example/oauth2/token', 'sa_123', 'https://api.example')
    expect(s).toContain("'https://id.example/oauth2/token'")
    expect(s).toContain('-u \'sa_123:\'"$CLIENT_SECRET"')
    expect(s).toContain('grant_type=client_credentials')
    expect(s).toContain("resource=https://api.example'")
  })
})
