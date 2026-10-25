# Identity providers and domain enrollment

## Add Google

1. In Google Cloud Console create an OAuth client of type *Web application* with the redirect URI
   `https://auth.example.com/login/google/callback` (shown as `callback_url` by the API).
2. `POST /api/v1/identity-providers` with `kind: google`, the client ID and secret. Optionally set `allowed_hds` to the
   Workspace domains you accept — tokens without a matching validated `hd` claim are refused.
3. Changes to providers need a recent sign-in (step-up, 5 minutes).
4. **Link your own Google account** before you sign in with it: as the owner created at setup, open **Account →
   Linked sign-in accounts → Link Google account**. A first Google sign-in with an email that already belongs to a
   Porch user is refused ("A Porch account with this email already exists"), so the owner is never duplicated.

Google cannot be asked to re-enter a password: for confirming sensitive actions and for linking, Porch asks for an
interactive Google sign-in (the account chooser) and accepts it. Other OpenID providers must perform a fresh sign-in
(`prompt=login`, `max_age=0`) and report it in `auth_time`.

## Sign in directly with Google

Under **Installation → Identity providers → Sign-in page**, choose **Go straight to Google**: `/login` then sends people
straight to Google. The full page, with every provider and the backup login, stays at `/login?all=1` (bookmark it).
Porch also shows the full page after a failed sign-in and after signing out, so nobody ends up in a loop. API:
`PUT /api/v1/installation/login` with `{"direct_provider": "google"}` (empty to turn it off; needs a recent sign-in).


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
