package keyring

// Columns is the single registry of every sealed column in the database (ADR-0003). Background resealing after a
// purpose-key rotation, the retire guard (a key version may be retired only when no registered column still uses it)
// and the backup/restore checks all read this list, so adding a sealed column without registering it here fails the
// registry test in internal/store.
var Columns = []Column{
	FieldColumn("audit_events", "id", "details_enc", PurposeField),
}
