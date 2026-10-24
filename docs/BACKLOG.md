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
- Admin UI: consolidate the per-section helpers written while the theme still failed contrast (`install/ConfirmAction`,
  `install/ManagedBy`, `tenant/common` `Tag`/`ProvenanceTag`/`Notice`, `authz/common` `ManagedBy`) back onto the kit.
- Assignment listings could carry display names for subjects, conditions and scopes so delegated admins with only
  `role:manage` do not see raw IDs.
- Re-enable dialog scroll locking once `react-remove-scroll` can be given the CSP nonce (ADR-0040).
- Security review deferrals (docs/SECURITY_REVIEW-2026-10-24.md): bind forward-auth codes to the browser (nonce
  cookie on the app host; L8); tokens of federated creators should follow the hourly upstream recheck (L3); burn
  authorization codes after the PKCE check and store issued IDs atomically (code-replay race); throttle
  `/login/{provider}/callback` before auditing state mismatches; treat a missing upstream `auth_time` as stale for
  step-up/linking; restrict claiming forward-auth hosts and `all_members` access mode by delegated admins.
- Per-tenant session lifetime overrides are stored but never applied (sessions do not record their tenant).
- Management API gaps found by the Terraform provider: single-object GETs for identity providers, domain rules,
  invites, memberships, assignments and shares; consistent ID-or-slug addressing (providers, applications, resources).
- Jellyfin integration beyond the documented matrix (third-party SSO plugin; mobile/TV clients lack OIDC).

## Known limitations

- Tenant isolation is logical (ADR-0004).
- Recovery answers are human-chosen; their strength is an estimate (ADR-0009).
