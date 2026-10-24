# Runbook: events (outbox → pulse)

Alerts: `PorchOutboxBacklog`, `PorchOutboxDeadLetters`. Health check `events`.

Porch writes every domain event to its outbox in the same transaction as the change and relays it to pulse
afterwards. Sign-ins and administration never wait for pulse.

1. Is the relay connected? The log says `event relay connected to pulse` at start, or repeats
   `event relay: cannot connect to pulse` every 30 s (URL, TLS CA or creds file wrong, or pulse down).
2. Backlog growing while connected: publishes fail. Check `porch_outbox_publish_total{result="error"}` and the last
   error logged; an expired or revoked pulse client credential shows as an authorization error — issue new creds in
   pulse and update `events.pulse.creds_file`, then restart Porch.
3. Dead letters: events that failed for 24 h or 50 attempts stop retrying. They stay in the database
   (`outbox.dead_at`) for inspection; consumers that need them must be reconciled from the audit log.
4. Consumers deduplicate on the event ID (`Nats-Msg-Id` / `ce-id`); delivery is at-least-once.
