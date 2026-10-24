---
layout: home
hero:
  name: Porch
  text: Identity for the people you live and build with
  tagline: Self-hosted single sign-on for families, friend groups and homelabs. One Go binary, one SQLite file.
  actions:
    - theme: brand
      text: What is Porch?
      link: /guide/what-is-porch
    - theme: alt
      text: Try it locally
      link: /guide/try-locally
    - theme: alt
      text: Project status
      link: /guide/status
features:
  - title: OIDC provider
    details: Authorization code + PKCE, RFC 9068 JWT access tokens, rotating refresh tokens with reuse detection.
  - title: Google federation
    details: Sign in with Google; enroll whole Workspace domains from the validated hd claim, never the email suffix.
  - title: Backup login that is hard to abuse
    details: Password plus your own titled recovery answers, with lockout that never touches Google login.
  - title: Tenants, roles and policies
    details: Several families on one install, database-enforced isolation, RBAC with expr conditions and an explain trace.
  - title: Forward-auth for everything else
    details: Protect apps without OIDC behind Caddy, Traefik or nginx, with identity headers and per-app access rules.
  - title: Automation built in
    details: Management API (OpenAPI 3.1), scoped automation tokens, a Terraform provider and events to pulse.
  - title: Backups you cannot read from the server
    details: age-encrypted to an offline recipient, uploaded to S3-compatible storage, with a tested restore drill.
---
