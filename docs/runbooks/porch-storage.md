# Runbook: SQLite storage

Alerts: `PorchStoreBusy`, `PorchSlowWrites`, `PorchWALLarge`.

Porch uses one writer connection (`BEGIN IMMEDIATE`) and keeps transactions free of network I/O, so busy retries mean
something outside Porch holds the database.

1. Another process? `fuser <data_dir>/porch.db` or `lsof`. Backup tools, `sqlite3` shells and file-sync agents must not
   open the live database; use `porch backup run` (M6) or the pre-migration snapshot instead.
2. Network or FUSE filesystem? Porch refuses to start on known network filesystems; slow disks still cause long writes.
   Move the data directory to local storage.
3. WAL growing: a long-lived reader blocks checkpoints. Restart readers, then Porch checkpoints within minutes
   (`porch_store_wal_bytes` drops).
4. Disk full: Porch degrades (`readyz` fails, new sessions and tokens are refused). Free space; it recovers after a
   successful write.
