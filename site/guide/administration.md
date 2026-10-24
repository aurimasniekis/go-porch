# Administer a tenant

A tenant (a family, a friend group, a homelab) is administered by its own members. Installation operators (the people
who run Porch) can do everything; everyone else needs a role in the tenant that grants the right permission.

## Who can do what

| Permission | Lets you |
|---|---|
| `member:manage` | add, suspend and remove members |
| `invite:manage` | invite people by email |
| `app:manage` | register applications (OpenID Connect or forward-auth), rotate client secrets |
| `group:manage` | create groups, add members, nest groups |
| `role:manage` | define roles and assign them; see effective permissions |
| `resource:manage` | define resources (folders, devices, …) that roles can be scoped to |
| `policy:manage` | write conditions and deny rules (needs a recent sign-in) |
| `service_account:manage` | create machine identities for scripts and APIs |
| `audit:read` | read this tenant's audit log |
| `authz:simulate` | use the access simulator |
| `tenant:manage` | rename the tenant and change its session lifetimes |

The built-in **Administrator** role grants everything (`*:*`). The built-in **Member** role is what every member has.

## You can only hand out what you hold

Porch refuses any change that would give someone more than you have yourself:

- assigning a role, or defining a role, with permissions you do not hold;
- adding someone to a group (or nesting a group under another) that is assigned such a role;
- removing an assignment, deleting a group or a role that carries permissions you do not hold;
- writing a deny rule for actions you do not hold, or loosening a condition that other people's roles depend on.

Grants you hold only under a condition (for example "only from the home network") or only on one resource do not
count. The API answers `403 privilege_escalation` and names what is missing; the admin UI shows the same message.

```mermaid
flowchart LR
  A[Dave: helpdesk role<br/>group:manage, role:manage, member:manage] -->|assign helpdesk to Bob| OK[allowed]
  A -->|assign Administrator to Bob| NO[refused: *:* not held]
  A -->|add Bob to group 'admins'<br/>which is assigned Administrator| NO2[refused]
```

Some things stay with installation operators because they affect every tenant: enabling or disabling a tenant,
sharing an application with another tenant, domain rules, identity providers, user accounts and other users' sessions.

## Service accounts

A service account is a tenant identity for a script or an API client. It gets a secret once, then requests access
tokens with the OAuth 2.0 client credentials grant:

```sh
curl -u "$SERVICE_ACCOUNT_ID:$SECRET" \
  -d grant_type=client_credentials \
  -d resource=https://api.smith.example \
  https://auth.example.com/oauth2/token
```

Tokens are short-lived JWTs (`sub` and `client_id` are the service account ID) for one of the audiences you
registered. Give the service account roles on the **Assignments** page like any member; disable it to stop it at once.
