package app

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/backup"
	"github.com/aurimasniekis/go-porch/internal/buildinfo"
	"github.com/aurimasniekis/go-porch/internal/config"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/netguard"
	"github.com/aurimasniekis/go-porch/internal/oidcop"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// ObjectStoreFor builds the S3 client of a backup configuration (dialing through the outbound guard).
func ObjectStoreFor(cfg *config.Config) (*backup.S3, error) {
	s := cfg.Backup.S3
	secret := s.SecretAccessKey
	if s.SecretAccessKeyFile != "" {
		b, err := os.ReadFile(s.SecretAccessKeyFile)
		if err != nil {
			return nil, fmt.Errorf("backup.s3.secret_access_key_file: %w", err)
		}
		secret = strings.TrimSpace(string(b))
	}
	var ca []byte
	if s.CAFile != "" {
		b, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("backup.s3.ca_file: %w", err)
		}
		ca = b
	}
	guard, err := netguard.New(cfg.Outbound.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	return backup.NewS3(backup.S3Options{Endpoint: s.Endpoint, Bucket: s.Bucket, Prefix: s.Prefix, Region: s.Region, AccessKey: s.AccessKeyID,
		SecretKey: secret, Insecure: s.Insecure, Lookup: s.Lookup, CAPEM: ca, CreateBucket: s.CreateBucket, Transport: guard.Transport()})
}

// initBackups builds the backup service (it exists even when backups are off, to report that state).
func (a *App) initBackups(kek *keyring.LocalKEK, objects backup.ObjectStore) error {
	o := backup.Options{Store: a.Store, Keyring: a.Keyring, Audit: a.Audit, Metrics: a.Metrics, Clock: a.Clock, Log: a.Log,
		Retention: a.Cfg.Backup.Retention, PorchVersion: buildinfo.Get().Version}
	if a.Cfg.Backup.Enabled {
		rs, err := backup.ParseRecipients(a.Cfg.Backup.Recipients)
		if err != nil {
			return err
		}
		o.Recipients = rs
		if objects == nil {
			s3, err := ObjectStoreFor(a.Cfg)
			if err != nil {
				return err
			}
			objects = s3
		}
		o.Objects = objects
		if !a.Cfg.Backup.ExcludeKEK {
			o.KEK = kek.Encoded
		}
	}
	a.Backups = backup.New(o)
	if a.Cfg.Backup.Enabled {
		if k, err := a.Backups.VerifyKey(); err == nil {
			a.Log.Info("backups enabled: store this verification key with the age identity (restores need it)", "verify_key", k)
		}
	}
	return nil
}

// backupLoop runs scheduled backups: one when the last success is older than the interval, retrying failures after
// 15 minutes.
func (a *App) backupLoop(ctx context.Context) {
	if !a.Cfg.Backup.Enabled {
		return
	}
	interval := a.Cfg.Backup.Interval.D()
	var lastAttempt time.Time
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		last, _ := a.Backups.LastSuccess(ctx)
		now := a.Clock.Now()
		if now.Sub(last) >= interval && now.Sub(lastAttempt) >= 15*time.Minute {
			lastAttempt = now
			_, _ = a.Backups.Run(ctx, "schedule", audit.System)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// finishRestore completes a restore left by `porch restore` (ADR-0042): every session and refresh token from the
// backup becomes invalid (new security epoch), signing keys are replaced, a critical alert stays open until
// acknowledged, and backup-login credentials are optionally wiped.
func (a *App) finishRestore(ctx context.Context, keys *oidcop.Keys) error {
	p, err := backup.ReadPending(a.Cfg.DataDir)
	if err != nil || p == nil {
		return err
	}
	err = a.Store.W().TxNamed(ctx, "backup.finish_restore", func(tx *store.Tx) error {
		if _, err := tx.Q.BumpSecurityEpoch(ctx, tx.NowMicros()); err != nil {
			return err
		}
		if p.InvalidateBackupCredentials {
			for _, q := range []string{"DELETE FROM backup_challenges", "DELETE FROM recovery_pairs", "DELETE FROM backup_credentials"} {
				if _, err := tx.SQL.ExecContext(ctx, q); err != nil {
					return err
				}
			}
		}
		msg := fmt.Sprintf("Porch was restored from backup %s (taken %s). All sessions and refresh tokens from before the restore are invalid; signing keys were replaced.",
			p.BackupID, p.BackupCreated.UTC().Format(time.RFC3339))
		if !p.Verified {
			msg += " The backup signature was NOT verified."
		}
		if err := tx.Q.InsertAlert(ctx, db.InsertAlertParams{ID: ids.New(ids.Alert), Kind: "installation_restored", Severity: "critical", Message: msg,
			CreatedAt: tx.NowMicros()}); err != nil {
			return err
		}
		_, err := a.Audit.Append(ctx, tx, audit.Event{Actor: audit.CLI, Action: "installation.restored", Target: audit.Target{Type: "backup", ID: p.BackupID},
			Details: map[string]any{"backup_created": p.BackupCreated.UTC().Format(time.RFC3339), "verified": p.Verified,
				"backup_logins_reset": p.InvalidateBackupCredentials}})
		return err
	})
	if err != nil {
		return fmt.Errorf("finish restore: %w", err)
	}
	for _, alg := range []string{"ES256", "RS256"} {
		if _, err := keys.Rotate(ctx, audit.CLI, alg, 0); err != nil {
			return fmt.Errorf("finish restore: rotate %s: %w", alg, err)
		}
	}
	if _, err := keys.RetireExpired(ctx); err != nil {
		return fmt.Errorf("finish restore: retire keys: %w", err)
	}
	a.Log.Warn("restore completed: sessions invalidated, signing keys rotated", "backup", p.BackupID, "verified", p.Verified)
	return backup.ClearPending(a.Cfg.DataDir)
}
