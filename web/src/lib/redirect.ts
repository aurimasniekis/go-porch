/** Same-origin path or "/" — mirrors httpx.SafeReturnTo on the server (T-B2-6). */
export function safeReturnTo(s: string | null | undefined, fallback = '/'): string {
  if (!s || s.length > 2048 || !s.startsWith('/') || s.startsWith('//') || s.startsWith('/\\')) return fallback
  for (const ch of s) {
    const c = ch.charCodeAt(0)
    if (c < 0x20 || c === 0x7f || ch === '\\') return fallback
  }
  return s
}

/** Friendly text for /login?error=<code> redirects from the portal. */
export function loginErrorMessage(code: string): string {
  switch (code) {
    case 'not_enrolled':
      return 'This account is not enrolled in Porch. Ask an administrator for an invitation.'
    case 'email_in_use':
      return 'A Porch account with this email already exists. Sign in another way (for example with your backup login), then link this account under Account → Linked sign-in accounts.'
    case 'domain_not_allowed':
      return "This account's Google Workspace domain is not allowed here."
    case 'expired':
      return 'The sign-in took too long or was started in another browser. Please try again.'
    case 'session_ended':
      return 'Your session ended because your account could not be re-confirmed with your identity provider.'
    case 'session_expired':
      return 'Your session has expired. Please sign in again.'
    case 'wrong_account':
      return 'You signed in with a different account than the one this session belongs to.'
    case 'stale_auth':
      return 'The identity provider did not perform a fresh sign-in. Please try again.'
    case 'already_linked':
      return 'That account is already linked to another Porch user.'
    case 'disabled':
      return 'This account is disabled.'
    case 'reauth_required':
      return 'Please sign in again to continue.'
    case 'unknown_provider':
      return 'That sign-in method is not available.'
    default:
      return 'Sign-in failed. Please try again.'
  }
}
