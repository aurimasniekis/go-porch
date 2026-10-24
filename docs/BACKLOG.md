# Backlog

Open items not yet scheduled into a milestone, plus known limitations. Items move into PLAN.md milestones when picked up.

## Open

- Front-channel / back-channel logout for downstream apps (v1 is RP-initiated only, ADR-0013).
- WebAuthn / passkeys as a second local factor or as the backup login.
- HA / multi-node (v1 is single-writer SQLite).
- KMS / Vault transit `KeyWrapper` implementations (interface exists via the keyring design).
- Real Google Directory API sync verification (fake-tested only).
- Jellyfin integration beyond the documented matrix (third-party SSO plugin; mobile/TV clients lack OIDC).

## Known limitations

- Tenant isolation is logical (ADR-0004).
- Recovery answers are human-chosen; their strength is an estimate (ADR-0009).
