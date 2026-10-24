# Monitoring

- `porch-dashboard.json` — Grafana dashboard (uid `porch-overview`): readiness, version, request rate/latency/errors by
  surface, sign-ins, backup-login lockouts, authorization decisions, tokens, outbox, SQLite write latency/busy/WAL,
  backups, Go runtime. Variables: Prometheus data source, `job`, `instance`.
- `porch-alerts.yaml` — Prometheus alerting rules; each alert links a runbook in `docs/runbooks/`.
- `porch-alerts.test.yaml` — `promtool test rules` unit tests.
- `check.sh` — validates the rules, runs the rule tests and parses every dashboard query with `promtool` (Docker).

Scrape the private management listener (never expose it publicly):

```yaml
scrape_configs:
  - job_name: porch
    static_configs:
      - targets: ['127.0.0.1:9464']
```

Labelled series (sign-ins, authorization decisions, tokens, outbox, backups) appear after their first event, so panels
can be empty on a fresh instance.
