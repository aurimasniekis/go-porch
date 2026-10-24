/** The per-request CSP nonce injected by the server into <meta name="porch-csp-nonce"> (ADR-0023). Mantine uses it
 * for the <style> elements it creates. */
export function cspNonce(): string {
  return document.querySelector<HTMLMetaElement>('meta[name="porch-csp-nonce"]')?.content ?? ''
}
