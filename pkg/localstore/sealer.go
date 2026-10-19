package localstore

import (
	"crypto/cipher"
	"errors"
)

// Sealer seals and opens blobs under a tenant's data key for a store that
// keeps its own files (the outbox, the content cache index). The purpose
// and the caller's name for each blob are bound into the additional data,
// so a blob moved to another name, purpose or tenant does not open.
type Sealer struct {
	s       *Store
	tenant  string
	purpose string
	gen     uint64
}

// Sealer returns a sealer for the tenant and purpose (creating the tenant's
// data key on first use).
func (s *Store) Sealer(tenant, purpose string) (*Sealer, error) {
	if err := validName(tenant); err != nil {
		return nil, err
	}
	if err := validName(purpose); err != nil {
		return nil, err
	}
	if _, err := s.tenantAEAD(tenant); err != nil {
		return nil, err
	}
	return &Sealer{s: s, tenant: tenant, purpose: purpose, gen: s.tenantGen(tenant)}, nil
}

func (z *Sealer) aead() (cipher.AEAD, error) { return z.s.tenantAEADGen(z.tenant, &z.gen) }

func (z *Sealer) binding(name string) binding {
	return binding{purpose: "sealer/" + z.purpose, tenant: z.tenant, name: name}
}

// Seal encrypts plaintext for name.
func (z *Sealer) Seal(name string, plaintext []byte) ([]byte, error) {
	if len(name) > maxNameLen*4 {
		return nil, ErrInvalidName
	}
	a, err := z.aead()
	if err != nil {
		return nil, err
	}
	return seal(a, kindSealer, z.binding(name), plaintext)
}

// Open authenticates and decrypts a blob sealed for name. A blob that does
// not authenticate is ErrTampered and is reported through OnTamper (the
// caller owns the file and decides where it goes).
func (z *Sealer) Open(name string, blob []byte) ([]byte, error) {
	if len(name) > maxNameLen*4 {
		return nil, ErrInvalidName
	}
	a, err := z.aead()
	if err != nil {
		return nil, err
	}
	pt, err := open(a, kindSealer, z.binding(name), blob)
	if errors.Is(err, errAuth) {
		z.s.tamper(TamperEvent{Tenant: z.tenant, Namespace: z.purpose, Name: name, Reason: "sealed blob failed authentication"})
		return nil, ErrTampered
	}
	return pt, err
}
