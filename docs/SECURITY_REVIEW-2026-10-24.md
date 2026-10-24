# Security review 2026-10-24 (M7)

Independent read-only review of the whole repository (an agent that did not write the code), with repro tests run
against in-process stacks. Findings, severity as reported, and their status after the fix pass. Regression tests are
named in the last column; "deferred" items are in `docs/BACKLOG.md`.

| ID | Severity | Finding | Status | Evidence |
|---|---|---|---|---|
| H1 | high | Forward-auth trusted client `X-Original-URL` (one cookie opened every forward-auth app behind Caddy/Traefik) | fixed: only `X-Forwarded-*` are read; test proxies now copy client headers like Caddy; nginx docs set `X-Forwarded-*` | `TestForwardAuthIgnoresClientOriginalURL` |
| H2 | high | Service-account rotate/update skipped the escalation check | fixed: rotate, update and delete need everything the service account holds | `TestReviewServiceAccountControl` |
| H3 | high | An operator's tenant token was not limited by its permission list when granting | fixed: automation tokens never get the operator exemption | `TestReviewOperatorTenantTokenLimited` |
| M1 | medium | Audience squatting across tenants (mint/introspect tokens for another tenant's API) | fixed: audiences belong to one tenant; client/service-account IDs refused | `TestReviewAudiencesTenantsAndLaunchURL` |
| M2 | medium | Expiring grants counted as held | fixed: escalation counts only unconditional, non-expiring tenant grants | `TestReviewExpiringGrantNotHeld` |
| M3 | medium | Removing a member kept their assignments (re-adding resurrected them); `member:manage` could suspend admins | fixed: trigger deletes assignments on every membership delete; suspend/remove need the member's permissions | `TestReviewMembershipCleanup` |
| M4 | medium | Deny policies ignored by the escalation check (an admin could delete a deny aimed at them); wildcard deny actions never matched | fixed: escalation evaluates deny policies for the caller; deny actions match with wildcard semantics | `TestReviewDenyPolicyBindsAdmin` |
| M5 | medium | Joining a group could satisfy a condition keyed on the group | fixed: group changes also need what policies naming the group unlock or block | `TestReviewGroupConditionGuarded` |
| M6 | medium | Installation admins / admin tokens could disable or delete owners | fixed: only owners act on owners, never the last active owner; tokens cannot disable/delete operators | `TestReviewOwnerProtection` |
| M7 | medium | Planted manifests made pruning delete real backups | fixed: retention and "latest" count only manifests this installation signed | `TestBackupRestoreDrill` (forged manifest) |
| M8 | medium | Restore resurrected revoked automation tokens | fixed: restore revokes all automation tokens; residual: secrets rotated after the backup come back (alert says so) | `TestBackupRestoreDrill` |
| M9 | medium | Disabled tenants' clients still got client-credentials tokens | fixed | `TestReviewAudiencesTenantsAndLaunchURL` |
| M10 | medium | Client credentials signed any requested scope | fixed: only registered scopes | `TestClientAuthAndClientCredentials` |
| M11 | medium | Deny policies on `principal.auth_method` failed open at code exchange/refresh | fixed: the sign-in method is stored with codes and refresh tokens | `TestDenyPolicyOnAuthMethodAtRefresh` |
| L1 | low | Role update could strip permissions the caller lacks; resource delete dropped others' scoped assignments (and left descendants' stale) | fixed | `TestReviewRoleStripGuarded` |
| L2 | low | Idempotent replay before authentication | fixed | `TestReviewIdempotencyNeedsAuthentication` |
| L3 | low | Automation tokens skip the hourly upstream recheck | deferred (documented in ADR-0044) | — |
| L4 | low | Token principals had `auth_time = now` | fixed: token creation time | `TestAutomationTokens` |
| L5 | low | Creating a service account / confidential client skipped step-up | fixed | app tests (setup sessions) |
| L6 | low | `launch_url` not validated on update | fixed | `TestReviewAudiencesTenantsAndLaunchURL` |
| L7 | low | `end_session` accepted any signed token as hint and revoked without a session (logout CSRF / token revocation DoS) | fixed: state changes only with an ID-token hint for the signed-in user | `TestRevocationAndEndSession` |
| L8 | low | Forward-auth login CSRF (code not bound to the browser) | deferred | — |
| L9 | low | Netguard missed IPv4-embedding IPv6 ranges | fixed | `TestEmbeddedIPv4Blocked` |
| L9 | low | Retiring signing keys survived a restore; unbounded object reads; interrupted restore skipped post-restore steps | fixed | `TestBackupRestoreDrill` |
| L9 | low | Code-replay race, unthrottled login-callback audit rows, missing `auth_time` treated as now, forward-auth host claiming by delegated admins | deferred | — |
| Info | — | Per-tenant session lifetimes are never applied (`SetTenant` unused) | documented; matrix corrected | — |

Also fixed from the Terraform provider work: policy `PUT` accepted a stale `If-Match`; role/group/resource/policy
deletes ignored `If-Match` and provenance; forward-auth create returned no hosts; idempotent replays lacked the ETag;
re-adding a group member or nesting edge was not idempotent.
