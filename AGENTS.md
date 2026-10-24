# AGENTS.md — rules for agents working on Porch

Porch is a security-sensitive identity provider. These rules apply to every agent session in this repository.

## Before working

1. Read `docs/PLAN.md` (milestones, definition of done), `docs/IMPLEMENTATION_MATRIX.md` (current status) and
   `docs/DECISIONS.md` (ADRs).
2. Consult `docs/THREAT_MODEL.md` for the security obligations of the area you touch.

## Contract rules

- **Never silently weaken security requirements.** Any relaxation must be an ADR in `docs/DECISIONS.md` labelled
  **security-relevant change**.
- **Distinguish implemented, tested and externally verified behaviour.** Never upgrade a matrix status without evidence
  from a command that ran and passed. Real Google, real S3 providers and real Cloudflare stay "not verified" unless
  actually tested.
- **No "done but unreachable" features**: a feature is done only when reachable from UI and/or API and tested.
- Do not invent cryptography; use the Go standard library, `golang.org/x/crypto`, go-jose, zitadel/oidc, go-oidc, age.
- Never commit secrets or secret-bearing fixtures; generate keys at test time.
- Write transactions (`store.Writer.Tx`) do no network I/O, sleeps or channel operations.
- Tenant-scoped data is accessed only through a `tenancy.Scope`.
- Adapted code from HallPass/Pulse keeps a provenance comment.

## Git workflow

- Work on `main`. One local Conventional Commit per verified milestone (or coherent sub-slice).
- Stage only relevant files by path; inspect the diff first.
- **Never push**, create tags, or open PRs without an explicit instruction for that specific action.
