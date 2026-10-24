package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/aurimasniekis/go-porch/internal/store"
)

// ErrUnverified means no supplied verification key matches the backup's signature.
var ErrUnverified = errors.New("backup: manifest signature does not verify with the supplied key(s); refusing to restore")

// Fetched is a downloaded, verified and decrypted backup.
type Fetched struct {
	Manifest Manifest
	DB       []byte
	KEK      []byte // nil when the KEK was not included
	Verified bool   // false only with SkipVerify
}

// FetchOptions select and check a backup.
type FetchOptions struct {
	ID         string // "" or "latest" for the newest complete backup
	Identities []age.Identity
	VerifyKeys []ed25519.PublicKey
	// SkipVerify restores without checking the manifest signature (dangerous: see ADR-0042).
	SkipVerify bool
}

// Fetch downloads a backup, verifies the manifest signature and every object's hash, and decrypts it.
func Fetch(ctx context.Context, objs ObjectStore, o FetchOptions) (*Fetched, error) {
	id := o.ID
	if id == "" || id == "latest" {
		// The newest backup that verifies (newest complete one only when verification is skipped).
		rs, err := ListVerified(ctx, objs, o.VerifyKeys)
		if err != nil {
			return nil, err
		}
		complete := false
		for _, r := range rs {
			complete = complete || r.Complete
			if r.Complete && (r.Verified || o.SkipVerify) {
				id = r.ID
				break
			}
		}
		if id == "" || id == "latest" {
			if complete {
				return nil, ErrUnverified
			}
			return nil, errors.New("backup: no complete backup found")
		}
	}
	env, m, err := readManifest(ctx, objs, id)
	if err != nil {
		return nil, err
	}
	f := &Fetched{Manifest: m}
	if !o.SkipVerify {
		if f.Verified = verifyEnvelope(env, o.VerifyKeys); !f.Verified {
			return nil, ErrUnverified
		}
	}
	for _, ob := range m.Objects {
		if ob.Key != objectKey(id, filepath.Base(ob.Key)) {
			return nil, fmt.Errorf("backup %s: object %q outside the backup", id, ob.Key)
		}
		ct, err := objs.Get(ctx, ob.Key)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", ob.Key, err)
		}
		if cs := sha256.Sum256(ct); hex.EncodeToString(cs[:]) != ob.StoredSHA256 {
			return nil, fmt.Errorf("backup %s: %s was modified in storage", id, ob.Name)
		}
		plain, err := open(o.Identities, ct)
		if err != nil {
			return nil, err
		}
		if ps := sha256.Sum256(plain); hex.EncodeToString(ps[:]) != ob.SHA256 || int64(len(plain)) != ob.Size {
			return nil, fmt.Errorf("backup %s: %s does not match the manifest", id, ob.Name)
		}
		switch ob.Name {
		case "db":
			f.DB = plain
		case "kek":
			f.KEK = plain
		}
	}
	if f.DB == nil {
		return nil, fmt.Errorf("backup %s: no database object", id)
	}
	return f, nil
}

// RestoreMarker is left in the data directory; the next Porch start completes the restore (new security epoch,
// signing-key rotation, alert, audit) and removes it.
const RestoreMarker = "restore-pending.json"

// Pending describes a restore the next start must finish.
type Pending struct {
	BackupID                    string    `json:"backup_id"`
	BackupCreated               time.Time `json:"backup_created"`
	RestoredAt                  time.Time `json:"restored_at"`
	Verified                    bool      `json:"verified"`
	InvalidateBackupCredentials bool      `json:"invalidate_backup_credentials"`
}

// RestoreOptions place a fetched backup.
type RestoreOptions struct {
	DataDir string
	// KEKFile receives the escrowed KEK (mode 0400). Leave empty to keep using an existing KEK (it must be the one the
	// backup's keyring was wrapped with).
	KEKFile                     string
	InvalidateBackupCredentials bool
	Now                         time.Time
}

// Restore writes a fetched backup into an empty data directory. It never overwrites existing files.
func Restore(f *Fetched, o RestoreOptions) error {
	if err := os.MkdirAll(o.DataDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(o.DataDir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("restore: data directory %s is not empty", o.DataDir)
	}
	if o.KEKFile != "" {
		if f.KEK == nil {
			return errors.New("restore: this backup does not include the KEK; omit the KEK file and supply the original KEK")
		}
		if _, err := os.Stat(o.KEKFile); err == nil {
			return fmt.Errorf("restore: %s already exists", o.KEKFile)
		}
	}
	// The marker goes first: a restore interrupted later leaves a marker without a complete data directory, which Porch
	// refuses to start from (CheckPending), instead of a database that skips the post-restore steps.
	p, err := json.Marshal(Pending{BackupID: f.Manifest.ID, BackupCreated: f.Manifest.Created, RestoredAt: o.Now.UTC(), Verified: f.Verified,
		InvalidateBackupCredentials: o.InvalidateBackupCredentials})
	if err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(o.DataDir, RestoreMarker), p, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(o.DataDir, store.DBFile+".restoring"), f.DB, 0o600); err != nil {
		return err
	}
	if o.KEKFile != "" {
		if err := os.MkdirAll(filepath.Dir(o.KEKFile), 0o700); err != nil {
			return err
		}
		if err := writeExclusive(o.KEKFile, bytes.TrimSpace(f.KEK), 0o400); err != nil {
			return err
		}
	}
	// Last step: the database appears under its real name only once everything else is in place.
	return os.Rename(filepath.Join(o.DataDir, store.DBFile+".restoring"), filepath.Join(o.DataDir, store.DBFile))
}

// CheckPending refuses to start from a data directory whose restore did not finish.
func CheckPending(dataDir string) error {
	p, err := ReadPending(dataDir)
	if err != nil || p == nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dataDir, store.DBFile)); err != nil {
		return fmt.Errorf("restore of backup %s did not finish (no %s); empty the data directory and run `porch restore` again",
			p.BackupID, store.DBFile)
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // operator-chosen restore target
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

// ReadPending returns the pending restore of a data directory, if any.
func ReadPending(dataDir string) (*Pending, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, RestoreMarker)) //nolint:gosec // fixed name inside the data dir
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("restore marker: %w", err)
	}
	return &p, nil
}

// ClearPending removes the marker after the restore was completed.
func ClearPending(dataDir string) error {
	return os.Remove(filepath.Join(dataDir, RestoreMarker))
}
