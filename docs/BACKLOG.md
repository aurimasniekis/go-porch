# Backlog

Open items not yet scheduled into a milestone, plus known limitations. Items move into PLAN.md milestones when picked up.

## Open

- Front-channel / back-channel logout for downstream apps (v1 is RP-initiated only, ADR-0013).
- WebAuthn / passkeys as a second local factor or as the backup login.
- HA / multi-node (v1 is single-writer SQLite).
- KMS / Vault transit `KeyWrapper` implementations (interface exists via the keyring design).
- Real Google Directory API sync verification (fake-tested only).
- `outbound.ca_file` for private upstream CAs (today the demo relies on Go's `SSL_CERT_DIR`, which works because the
  SSRF-guarded transport leaves `TLSClientConfig` unset).
- Accept a KEK delivered by systemd `LoadCredential=` (`$CREDENTIALS_DIRECTORY`, ACL mask 0440); the shipped unit reads a
  0400 file owned by the `porch` user instead (deploy/systemd/README.md).
- Test-only custom-issuer Google provider so the demo stack can run in production mode.
- Proxy examples: strip the `__Host-porch_fa` cookie from requests forwarded to the backend after `forward_auth`.
- Jellyfin integration beyond the documented matrix (third-party SSO plugin; mobile/TV clients lack OIDC).

## Known limitations

- Tenant isolation is logical (ADR-0004).
- Recovery answers are human-chosen; their strength is an estimate (ADR-0009).
