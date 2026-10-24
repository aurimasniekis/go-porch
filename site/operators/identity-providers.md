# Identity providers and domain enrollment

## Add Google

1. In Google Cloud Console create an OAuth client of type *Web application* with the redirect URI
   `https://auth.example.com/login/google/callback` (shown as `callback_url` by the API).
2. `POST /api/v1/identity-providers` with `kind: google`, the client ID and secret. Optionally set `allowed_hds` to the
   Workspace domains you accept — tokens without a matching validated `hd` claim are refused.
3. Changes to providers need a recent sign-in (step-up, 5 minutes).


## Domain rules

`POST /api/v1/tenants/{tenant}/domain-rules`:

| Field | Values | Meaning |
|---|---|---|
| `evidence_kind` | `workspace_hd` | The validated `hd` claim of a Google ID token equals the domain (strong) |
| | `verified_email` | The email domain of a verified email (weaker: anyone with an address there qualifies) |
| `mode` | `jit` | Create the user and membership on first login |
| | `invite_only` | Also require an open invite for the exact (verified) email |

Memberships created by a rule carry `source: domain_rule:<id>`. When the evidence disappears (the account leaves the
Workspace, the rule is deleted), Porch removes those memberships; manual memberships are never removed automatically.
The `hd=` hint Porch sends to Google only pre-selects the account picker and is never trusted.

## Invites

`POST /api/v1/tenants/{tenant}/invites` with an email. The invite is consumed by the first upstream login whose
*verified* email matches.
