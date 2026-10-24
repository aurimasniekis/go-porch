# Runbook: elevated server errors or latency

Alerts: `PorchHighServerErrorRate`, `PorchSlowRequests`.

1. Find the surface (`portal`, `api`, `oidc`, `outpost`) on the Porch dashboard ("Responses by status class",
   "p95 latency by surface").
2. Logs carry a `request_id` for every request; search for `level=ERROR` around the alert time. API errors are logged
   as `api error op=…` without secrets.
3. Storage problems show up as 5xx everywhere at once: check the Storage row (busy retries, write p95) and
   `porch-storage.md`.
4. Only `oidc` slow: signing is CPU-bound (RS256 3072-bit keys are slower than ES256); check CPU and whether a client
   requests RS256 unnecessarily.
5. Only `outpost` slow or failing: the reverse proxy calls `/outpost/auth` on every request; check the proxy's
   timeouts and that it reaches Porch directly (not through Cloudflare).
