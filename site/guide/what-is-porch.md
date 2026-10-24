# What is Porch?

Porch is a self-hosted identity provider for small groups: a family, a group of friends sharing services, or a homelab.
It sits in front of your apps and answers two questions: **who is this person?** and **may they use this app?**

- Apps that speak OpenID Connect (Grafana, Immich, Nextcloud, your own) use Porch as their login provider.
- Apps that don't are protected with **forward-auth** through Caddy, Traefik or nginx.
- People sign in with **Google** (or a Google Workspace domain) and keep a **backup login** for when Google is unavailable.
- One installation can host several **tenants** (for example three families) that share some apps and keep others private.

Porch is deliberately smaller than Authentik or Keycloak: one binary, one SQLite database, one key file.

See [Project status](./status) for what each feature is covered by.
