// Package localstore is the sensor's encrypted, crash-safe local store: the
// key hierarchy and the sealed records that the outbox, the job journal, the
// content cache index and the policy cache are kept in.
//
// # Layout
//
// One directory, used by one process at a time (flock), 0700, every file
// 0600:
//
//	<dir>/master.key             the store master key, only when no key file is
//	                             configured (Options.KeyFile); see "Keys"
//	<dir>/meta.rec               boot generation (sealed with the master key)
//	<dir>/keys/<tenant>.key      the tenant's data key, wrapped by the master key
//	<dir>/kv/<tenant>/<ns>/<name>.rec   sealed key/value records
//	<dir>/corrupt/               records that failed authentication, quarantined
//	<dir>/tmp/                   temporary files of in-progress writes
//
// # Keys
//
// The master key (32 random bytes) comes from Options.KeyFile when it is set
// (a mounted secret, a tmpfs file: keep it off the data volume so a copy of
// the volume alone reveals nothing), else from <dir>/master.key, created on
// first use. It never encrypts data itself: it wraps one random data key per
// tenant (AES-256-GCM, the tenant id in the additional data). An organization
// sensor uses the tenant SensorTenant; a shared sensor uses one tenant per
// organization whose jobs it holds.
//
// EraseTenant deletes the tenant's wrapped key first (crypto-erase: whatever
// copy of the records survives, on a snapshot or in a flash translation
// layer, can no longer be decrypted), then removes its records best effort.
// Data keys are random rather than derived from the master key precisely so
// that this erasure holds while the master key lives on.
//
// A missing master key while wrapped keys exist is an error (ErrKeyMissing):
// the store never silently creates a new key that would orphan every record.
//
// # Records
//
// Every record is sealed with AES-256-GCM under its tenant's data key. The
// additional data binds the record to its purpose, tenant, namespace and
// name, so a file copied over another name, another namespace or another
// tenant's directory fails authentication. Writes go to tmp/, are fsynced,
// renamed into place and the directory is fsynced: a crash leaves the old
// record or the new one, never a torn one. A record that fails
// authentication (a torn write on a lying disk, a foreign or edited file) is
// moved to corrupt/, counted, reported through Options.OnTamper and returned
// as ErrTampered; it never crashes the process.
//
// # What encryption at rest protects
//
// It protects queued results, journals, cached policy and credentials from
// someone who obtains a copy of the data volume (a snapshot, a backup, a
// disk taken from a decommissioned host, a volume attached elsewhere), and
// it detects offline changes to any record. It does not protect against
// root on the running host or against the sensor process itself, and when
// the master key file sits on the same volume it gives integrity and tenant
// separation but not confidentiality against a full copy of that volume.
// Doctor reports where the key lives.
//
// # Disk space
//
// Disk reports the free space of the store's volume: DiskLow tells the
// caller to stop accepting new work; at DiskCritical only writes marked
// Critical (journal and state updates) are accepted, so a full disk never
// corrupts a record and never blocks a deletion.
//
// Stability: Experimental (docs/STABILITY.md).
package localstore
