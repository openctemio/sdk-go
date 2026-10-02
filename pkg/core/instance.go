package core

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

var (
	processInstanceOnce sync.Once
	processInstanceID   string
)

// ProcessInstanceID returns the random id this process picked when it first
// asked: 32 hex characters, the same for the life of the process, different
// on every start. Heartbeats carry it as "instance_id" so the platform can
// tell a restart (the id changes once) from one key running in two places
// (two ids alternate), and flag a copied or shared key (api RFC-032 Phase 0).
// It identifies a process, not a host or a sensor, and carries no secret.
func ProcessInstanceID() string {
	processInstanceOnce.Do(func() {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			// crypto/rand does not fail on supported platforms; an empty id
			// only turns clone detection off for this process.
			return
		}
		processInstanceID = hex.EncodeToString(b)
	})
	return processInstanceID
}
