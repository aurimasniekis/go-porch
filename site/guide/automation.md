# API and Terraform

Everything the admin UI does goes through the management API at `/api/v1`, described by an OpenAPI 3.1 document
([`api/openapi.json`](https://github.com/aurimasniekis/go-porch/blob/main/api/openapi.json), also served at
`/api/v1/openapi.json`). The UI is just another client.

## Automation tokens

Scripts and Terraform authenticate with an **automation token** (`porch_at_…`) sent as
`Authorization: Bearer porch_at_…`. Issue one in the admin UI under **Automation tokens**. It is shown once.

- An **installation token** with role `admin` manages everything, including tenants, users, identity providers and
  domain rules. With role `inspector` it reads the configuration of every tenant and changes nothing; with role
  `auditor` it reads installation health and the audit log. Only an installation owner can issue one, and only after
  a recent sign-in.
- A **tenant token** is limited to one tenant and to a list of permissions its issuer holds. Delegated
  administrators can issue tenant tokens for their tenant. A change that would grant more than the issuer holds fails
  with `403 privilege_escalation`. A token with only `:read` permissions (for example `app:read` and
  `service_account:read`) can look but not change anything.

Tokens expire after 1–366 days and can be revoked at any time. Porch stores only a hash of the token. Tokens of users
who sign in with Google stop working when that person has not signed in to Google through Porch within
`automation.upstream_max_age` (default 30 days).

An installation owner can also issue an installation token that **never expires** ("Never expires" in the token
dialog, or `"never_expires": true`). It keeps working without an expiry and without Google confirming the owner, so
your Terraform still works during a Google outage, or while you repair the Google setup itself. Treat it like a root
password: anyone holding it can manage the installation until you revoke it. It stops if its owner is disabled or
loses the owner role.

### Tokens that issue tokens

A token can issue other tokens, so Terraform can create the tokens your integrations need:

- an installation `admin` token issued by an owner issues installation tokens of any role and tenant tokens; a tenant
  token issues tenant tokens for its own tenant, with permissions it holds;
- read-only tokens (`auditor`, `inspector`, or tenant tokens with only `:read` permissions) issue nothing;
- an issued token never outlives the token that issued it, and only a token that never expires can issue one that
  never expires;
- revoking a token also revokes every token it issued, so revoking a leaked token ends everything minted from it.

The token list shows which token issued each one.

<Shot name="tokens" alt="Automation tokens, one issued by the Terraform token" caption="app-catalogue was issued by the terraform token" />

With Terraform (provider 0.2 and later), `porch_automation_token` issues such a token and keeps its secret in state:

```hcl
resource "porch_automation_token" "catalogue" {
  name            = "catalogue"
  role            = "inspector"
  expires_in_days = 180
}
```

```sh
curl -fsS -H "Authorization: Bearer $PORCH_TOKEN" https://auth.example.com/api/v1/tenants/smith/members
```

Writes support `If-Match` with the object's `ETag`, so concurrent changes fail with `412` instead of overwriting each
other. Creates accept an `Idempotency-Key` header, so a retried request does not create a duplicate. Responses that
contain a secret are never replayed.

## Terraform

The [Terraform provider](https://github.com/aurimasniekis/terraform-provider-porch) manages tenants, users and
memberships, identity providers and domain rules, applications and shares, groups, roles, resources, policies,
assignments and service accounts, with import for each.

```hcl
terraform {
  required_providers {
    porch = {
      source  = "aurimasniekis/porch"
      version = "~> 0.1"
    }
  }
}

provider "porch" {
  endpoint = "https://auth.example.com" # or PORCH_ENDPOINT
  token    = var.porch_token            # or PORCH_TOKEN
}

resource "porch_policy" "daytime" {
  tenant     = porch_tenant.smith.id
  slug       = "daytime"
  name       = "Daytime only (07:00-21:00 UTC)"
  effect     = "condition"
  expression = "context.hour >= 7 && context.hour < 21"
}

# Kids may open the media apps, but only during the day.
resource "porch_role_assignment" "kids_media" {
  tenant              = porch_tenant.smith.id
  subject_type        = "group"
  subject_id          = porch_group.kids.id
  role_id             = porch_role.media_viewer.id
  condition_policy_id = porch_policy.daytime.id
}
```

The provider is published to the
[Terraform Registry](https://registry.terraform.io/providers/aurimasniekis/porch) (`terraform init` installs it; the
checksums are GPG-signed). Its
[`examples/families`](https://github.com/aurimasniekis/terraform-provider-porch/tree/main/examples/families) scenario
sets up three families, shared applications, nested groups, a daytime-only policy and a service account (69
resources). It is applied, re-planned with no changes and destroyed against a real Porch in CI.

Objects created by Terraform carry a `terraform` badge in the admin UI (`managed_by`), with a reminder that manual
changes are overwritten on the next apply. This is a hint, not a lock.

## Events

Porch records domain events (tenants, memberships, users, applications and shares, identity providers and domain
rules created, updated or deleted) in an outbox in the same transaction as the change. A relay publishes them to
[pulse](https://github.com/aurimasniekis/go-pulse) over NATS JetStream as `evt.porch.<area>.<entity>.<action>`, with a
stable event ID for de-duplication. Pulse being down never blocks sign-in. The relay is tested against an embedded NATS JetStream server and against a running
`pulsed` (`test/pulse/verify.sh`): events arrive with Porch's IDs, events written while pulse is down are delivered
when it returns, and restarting Porch publishes nothing twice.
