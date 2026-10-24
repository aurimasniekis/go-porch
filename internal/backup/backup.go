// Package backup writes encrypted backups of the Porch database (and, by default, its KEK) to S3-compatible storage
// and restores them into a clean data directory (ADR-0042).
//
// Each backup is a snapshot (VACUUM INTO) compressed with S2 and encrypted with age to offline recipients, so Porch
// can write backups but not read them. A plaintext manifest, written last, lists the objects with their SHA-256 and is
// signed with an Ed25519 key derived from the keyring: age recipients are public, so without the signature anyone
// with write access to the bucket could plant a forged installation encrypted to the same recipients.
package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/aurimasniekis/go-porch/internal/audit"
	"github.com/aurimasniekis/go-porch/internal/clock"
	"github.com/aurimasniekis/go-porch/internal/domain"
	"github.com/aurimasniekis/go-porch/internal/ids"
	"github.com/aurimasniekis/go-porch/internal/installation"
	"github.com/aurimasniekis/go-porch/internal/keyring"
	"github.com/aurimasniekis/go-porch/internal/obs/metrics"
	"github.com/aurimasniekis/go-porch/internal/store"
	"github.com/aurimasniekis/go-porch/internal/store/db"
)

// Object layout under the store prefix.
const (
	backupPrefix = "backups/"
	dbObject     = "db.age"
	kekObject    = "kek.age"
	manifestName = "manifest.json"
)

func objectKey(id, name string) string { return backupPrefix + id + "/" + name }

// ManifestVersion is the manifest format version.
const ManifestVersion = 1

// Manifest describes one backup. It holds no secrets.
type Manifest struct {
	Version        int       `json:"v"`
	ID             string    `json:"id"`
	Created        time.Time `json:"created"`
	PorchVersion   string    `json:"porch_version"`
	SchemaVersion  int64     `json:"schema_version"`
	InstallationID string    `json:"installation_id"`
	KEKID          string    `json:"kek_id"`
	KEKIncluded    bool      `json:"kek_included"`
	Objects        []Object  `json:"objects"`
}

// Object is one encrypted file of a backup.
type Object struct {
	Name         string `json:"name"` // "db" or "kek"
	Key          string `json:"key"`
	Size         int64  `json:"size"`   // plaintext bytes
	SHA256       string `json:"sha256"` // of the plaintext
	StoredSize   int64  `json:"stored_size"`
	StoredSHA256 string `json:"stored_sha256"`
}

// envelope is the stored manifest.json: the exact manifest bytes and their signature.
type envelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	KeyID     string          `json:"key_id"`
	Signature string          `json:"signature"`
}

// VerifyKeyPrefix marks backup verification keys.
const VerifyKeyPrefix = "porch-backup-ed25519:"

// FormatVerifyKey encodes a public verification key.
func FormatVerifyKey(pub ed25519.PublicKey) string {
	return VerifyKeyPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

// ParseVerifyKey decodes a verification key.
func ParseVerifyKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), VerifyKeyPrefix))
	if err != nil || len(b) != ed25519.PublicKeySize || !strings.HasPrefix(strings.TrimSpace(s), VerifyKeyPrefix) {
		return nil, errors.New("backup: invalid verification key (want porch-backup-ed25519:…)")
	}
	return ed25519.PublicKey(b), nil
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// SigningKey derives the installation's backup signing key from the keyring backup-meta purpose key. Rotating that
// purpose key changes the verification key; older backups stay verifiable with the old public key.
func SigningKey(kr *keyring.Keyring) (ed25519.PrivateKey, error) {
	seed, err := kr.MAC(keyring.PurposeBackupMeta, []byte("porch/backup-signing/v1"))
	if err != nil {
		return nil, err
	}
	if len(seed) < ed25519.SeedSize {
		return nil, errors.New("backup: short signing seed")
	}
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize]), nil
}

// Options configure the service.
type Options struct {
	Store      *store.Store
	Keyring    *keyring.Keyring
	Audit      *audit.Writer
	Metrics    *metrics.Metrics
	Clock      clock.Clock
	Log        *slog.Logger
	Objects    ObjectStore
	Recipients []age.Recipient
	// KEK returns the encoded KEK to escrow; nil leaves the KEK out of backups.
	KEK          func() []byte
	Retention    int
	PorchVersion string
}

// Service runs backups.
type Service struct{ o Options }

// New returns the service.
func New(o Options) *Service {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	return &Service{o: o}
}

// VerifyKey returns the public key that verifies this installation's backups.
func (s *Service) VerifyKey() (string, error) {
	k, err := SigningKey(s.o.Keyring)
	if err != nil {
		return "", err
	}
	return FormatVerifyKey(k.Public().(ed25519.PublicKey)), nil
}

// Run is one backup attempt.
type Run struct {
	ID          string     `json:"id"`
	Trigger     string     `json:"trigger" enum:"schedule,manual,cli"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	OK          *bool      `json:"ok,omitempty"`
	Error       string     `json:"error,omitempty"`
	DBBytes     int64      `json:"db_bytes"`
	StoredBytes int64      `json:"stored_bytes"`
	KEKIncluded bool       `json:"kek_included"`
	Pruned      int64      `json:"pruned"`
}

func runFromRow(r db.BackupRun) Run {
	out := Run{ID: r.ID, Trigger: r.Trigger, StartedAt: domain.FromMicros(r.StartedAt), FinishedAt: domain.OptMicros(r.FinishedAt), Error: r.Error,
		DBBytes: r.DbBytes, StoredBytes: r.StoredBytes, KEKIncluded: r.KekIncluded == 1, Pruned: r.Pruned}
	if r.Ok.Valid {
		ok := r.Ok.Int64 == 1
		out.OK = &ok
	}
	return out
}

// Runs returns the most recent runs, newest first.
func (s *Service) Runs(ctx context.Context, limit int) ([]Run, error) {
	rows, err := s.o.Store.R().ListBackupRuns(ctx, int64(limit))
	if err != nil {
		return nil, err
	}
	out := make([]Run, 0, len(rows))
	for _, r := range rows {
		out = append(out, runFromRow(r))
	}
	return out, nil
}

// LastSuccess returns the time of the last successful backup (zero if none).
func (s *Service) LastSuccess(ctx context.Context) (time.Time, error) {
	r, err := s.o.Store.R().LastSuccessfulBackupRun(ctx)
	if err != nil {
		return time.Time{}, nil //nolint:nilerr // no successful run yet
	}
	return domain.FromMicros(r.StartedAt), nil
}

// Run takes a backup now. trigger is schedule, manual or cli.
func (s *Service) Run(ctx context.Context, trigger string, actor audit.Actor) (Run, error) {
	id := ids.New(ids.BackupRun)
	start := s.o.Clock.Now()
	if err := s.o.Store.W().TxNamed(ctx, "backup.start", func(tx *store.Tx) error {
		return tx.Q.InsertBackupRun(ctx, db.InsertBackupRunParams{ID: id, Trigger: trigger, StartedAt: tx.NowMicros()})
	}); err != nil {
		return Run{}, err
	}
	m, stored, pruned, err := s.run(ctx, id, start)
	ok := err == nil
	msg := ""
	if err != nil {
		msg = err.Error()
		s.o.Log.Error("backup failed", "id", id, "err", err)
	} else {
		s.o.Log.Info("backup complete", "id", id, "stored_bytes", stored, "pruned", pruned)
	}
	var dbBytes int64
	for _, o := range m.Objects {
		if o.Name == "db" {
			dbBytes = o.Size
		}
	}
	finishErr := s.o.Store.W().TxNamed(context.WithoutCancel(ctx), "backup.finish", func(tx *store.Tx) error {
		if err := tx.Q.FinishBackupRun(ctx, db.FinishBackupRunParams{FinishedAt: domain.NullMicros(&tx.Now), Ok: sqlBool(ok), Error: msg,
			DbBytes: dbBytes, StoredBytes: stored, KekIncluded: boolInt(m.KEKIncluded), Pruned: pruned, ID: id}); err != nil {
			return err
		}
		ev := audit.Event{Actor: actor, Action: "backup.completed", Target: audit.Target{Type: "backup", ID: id},
			Details: map[string]any{"trigger": trigger, "stored_bytes": stored, "kek_included": m.KEKIncluded, "pruned": pruned}}
		if !ok {
			ev.Action, ev.Outcome, ev.ReasonCode, ev.Details = "backup.failed", audit.OutcomeFailure, "backup_error", map[string]any{"trigger": trigger, "error": msg}
		}
		_, err := s.o.Audit.Append(ctx, tx, ev)
		return err
	})
	s.o.Metrics.BackupRun(ok, s.o.Clock.Now())
	if err == nil {
		err = finishErr
	}
	rows, _ := s.Runs(ctx, 50)
	for _, r := range rows {
		if r.ID == id {
			return r, err
		}
	}
	return Run{ID: id, Trigger: trigger, StartedAt: start}, err
}

func (s *Service) run(ctx context.Context, id string, start time.Time) (Manifest, int64, int64, error) {
	m := Manifest{Version: ManifestVersion, ID: id, Created: start.UTC(), PorchVersion: s.o.PorchVersion, KEKID: s.o.Keyring.KEKID()}
	if s.o.Objects == nil || len(s.o.Recipients) == 0 {
		return m, 0, 0, errors.New("backups are not configured")
	}
	if c, ok := s.o.Objects.(interface{ Check(context.Context) error }); ok {
		if err := c.Check(ctx); err != nil {
			return m, 0, 0, err
		}
	}
	inst, err := installation.Get(ctx, s.o.Store.R())
	if err != nil {
		return m, 0, 0, err
	}
	m.InstallationID = inst.ID
	if m.SchemaVersion, _, err = store.SchemaVersions(ctx, s.o.Store.ReadDB(), store.EmbeddedMigrations()); err != nil {
		return m, 0, 0, err
	}
	dir, err := os.MkdirTemp(s.o.Store.Dir(), ".backup-")
	if err != nil {
		return m, 0, 0, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	snap := filepath.Join(dir, store.DBFile)
	if err := s.o.Store.Snapshot(ctx, snap); err != nil {
		return m, 0, 0, err
	}
	plain, err := os.ReadFile(snap) //nolint:gosec // our own temp file
	if err != nil {
		return m, 0, 0, err
	}
	var stored int64
	put := func(name, file string, data []byte) error {
		ct, err := seal(s.o.Recipients, data)
		if err != nil {
			return err
		}
		key := objectKey(id, file)
		if err := s.o.Objects.Put(ctx, key, ct); err != nil {
			return fmt.Errorf("upload %s: %w", file, err)
		}
		ps, cs := sha256.Sum256(data), sha256.Sum256(ct)
		m.Objects = append(m.Objects, Object{Name: name, Key: key, Size: int64(len(data)), SHA256: hex.EncodeToString(ps[:]),
			StoredSize: int64(len(ct)), StoredSHA256: hex.EncodeToString(cs[:])})
		stored += int64(len(ct))
		return nil
	}
	if err := put("db", dbObject, plain); err != nil {
		return m, stored, 0, err
	}
	if s.o.KEK != nil {
		m.KEKIncluded = true
		if err := put("kek", kekObject, s.o.KEK()); err != nil {
			return m, stored, 0, err
		}
	}
	env, err := s.sign(m)
	if err != nil {
		return m, stored, 0, err
	}
	if err := s.o.Objects.Put(ctx, objectKey(id, manifestName), env); err != nil {
		return m, stored, 0, fmt.Errorf("upload manifest: %w", err)
	}
	stored += int64(len(env))
	pruned, err := s.prune(ctx)
	if err != nil {
		s.o.Log.Warn("backup prune", "err", err) // the backup itself succeeded
	}
	return m, stored, pruned, nil
}

func (s *Service) sign(m Manifest) ([]byte, error) {
	k, err := SigningKey(s.o.Keyring)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Manifest: body, KeyID: keyID(k.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, body))})
}

// Remote is a backup found in storage.
type Remote struct {
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	Complete bool      `json:"complete"`
	Manifest *Manifest `json:"manifest,omitempty"`
	KeyID    string    `json:"key_id,omitempty"`
	Bytes    int64     `json:"bytes"`
	// Verified is set by ListVerified when a supplied key verifies the manifest.
	Verified bool `json:"verified"`
	env      envelope
}

// List returns the backups in storage, newest first. Manifests are parsed but not verified.
func List(ctx context.Context, objs ObjectStore) ([]Remote, error) {
	infos, err := objs.List(ctx, backupPrefix)
	if err != nil {
		return nil, err
	}
	byID := map[string]*Remote{}
	for _, o := range infos {
		rest := strings.TrimPrefix(o.Key, backupPrefix)
		id, name, ok := strings.Cut(rest, "/")
		if !ok || !ids.Valid(ids.BackupRun, id) {
			continue
		}
		r := byID[id]
		if r == nil {
			r = &Remote{ID: id, Created: o.ModTime}
			byID[id] = r
		}
		r.Bytes += o.Size
		if name == manifestName {
			r.Complete = true
		}
	}
	out := make([]Remote, 0, len(byID))
	for _, r := range byID {
		if r.Complete {
			if env, m, err := readManifest(ctx, objs, r.ID); err == nil {
				r.Manifest, r.Created, r.KeyID, r.env = &m, m.Created, env.KeyID, env
			}
		}
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b Remote) int { return strings.Compare(b.ID, a.ID) })
	return out, nil
}

// ListVerified is List with Verified set for manifests that one of keys verifies. Unverified manifests may have been
// planted by anyone with write access to the bucket.
func ListVerified(ctx context.Context, objs ObjectStore, keys []ed25519.PublicKey) ([]Remote, error) {
	rs, err := List(ctx, objs)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		rs[i].Verified = rs[i].Manifest != nil && verifyEnvelope(rs[i].env, keys)
	}
	return rs, nil
}

func verifyEnvelope(env envelope, keys []ed25519.PublicKey) bool {
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		return false
	}
	for _, k := range keys {
		if ed25519.Verify(k, env.Manifest, sig) {
			return true
		}
	}
	return false
}

func readManifest(ctx context.Context, objs ObjectStore, id string) (envelope, Manifest, error) {
	var env envelope
	var m Manifest
	b, err := objs.Get(ctx, objectKey(id, manifestName))
	if err != nil {
		return env, m, err
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return env, m, fmt.Errorf("backup %s: bad manifest: %w", id, err)
	}
	if err := json.Unmarshal(env.Manifest, &m); err != nil {
		return env, m, fmt.Errorf("backup %s: bad manifest: %w", id, err)
	}
	if m.ID != id || m.Version != ManifestVersion {
		return env, m, fmt.Errorf("backup %s: manifest does not match its location", id)
	}
	return env, m, nil
}

// prune deletes verified backups beyond the retention count (newest kept) and incomplete ones older than a day.
// Complete backups whose manifest this installation did not sign are neither counted nor deleted: a planted manifest
// must not push real backups out of retention (security review M7).
func (s *Service) prune(ctx context.Context) (int64, error) {
	k, err := SigningKey(s.o.Keyring)
	if err != nil {
		return 0, err
	}
	rs, err := ListVerified(ctx, s.o.Objects, []ed25519.PublicKey{k.Public().(ed25519.PublicKey)})
	if err != nil {
		return 0, err
	}
	kept := 0
	var n int64
	for _, r := range rs { // newest first
		del := false
		if r.Complete && !r.Verified {
			s.o.Log.Warn("backup storage holds a manifest this installation did not sign; ignoring it", "id", r.ID)
			continue
		}
		if r.Complete {
			kept++
			del = kept > max(s.o.Retention, 1)
		} else {
			del = s.o.Clock.Now().Sub(r.Created) > 24*time.Hour
		}
		if !del {
			continue
		}
		objs, err := s.o.Objects.List(ctx, backupPrefix+r.ID+"/")
		if err != nil {
			return n, err
		}
		// Manifest first: a half-deleted backup is then incomplete, never a complete one with missing objects.
		slices.SortFunc(objs, func(a, b ObjectInfo) int {
			return boolCmp(strings.HasSuffix(b.Key, manifestName), strings.HasSuffix(a.Key, manifestName))
		})
		for _, o := range objs {
			if err := s.o.Objects.Delete(ctx, o.Key); err != nil {
				return n, fmt.Errorf("delete %s (object lock?): %w", o.Key, err)
			}
		}
		n++
	}
	return n, nil
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func sqlBool(b bool) sql.NullInt64 { return sql.NullInt64{Int64: boolInt(b), Valid: true} }
