// Package truststore holds the public keys a verifier is willing to accept.
// It is distributed out of band (copied manually in DDIL conditions).
package truststore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	ErrUnknownKey = errors.New("key_id tidak ada di trust store")
	ErrRevoked    = errors.New("kunci berstatus revoked")
	ErrNotValidAt = errors.New("di luar masa berlaku kunci (not_before/not_after)")
)

type Key struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	PublicKey string    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Status    string    `json:"status"` // active | revoked
}

type Store struct {
	Version int   `json:"version"`
	Keys    []Key `json:"keys"`
}

func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trust store: %w", err)
	}
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("trust store %s: %w", path, err)
	}
	return s, nil
}

// Parse reads a trust store from bytes; used where there is no filesystem (browser demo).
func Parse(data []byte) (*Store, error) {
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadOrEmpty is used by keygen when enrolling the first key.
func LoadOrEmpty(path string) (*Store, error) {
	s, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Store{Version: 1}, nil
	}
	return s, err
}

func (s *Store) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (s *Store) Upsert(k Key) {
	for i := range s.Keys {
		if s.Keys[i].KeyID == k.KeyID {
			s.Keys[i] = k
			return
		}
	}
	s.Keys = append(s.Keys, k)
}

// Lookup returns the trusted public key for keyID at time at.
func (s *Store) Lookup(keyID string, at time.Time) (ed25519.PublicKey, error) {
	for _, k := range s.Keys {
		if k.KeyID != keyID {
			continue
		}
		if k.Status != "active" {
			return nil, ErrRevoked
		}
		if at.Before(k.NotBefore) || at.After(k.NotAfter) {
			return nil, ErrNotValidAt
		}
		if k.Algorithm != "ed25519" {
			return nil, fmt.Errorf("algoritma tidak didukung: %q", k.Algorithm)
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("kunci publik di trust store rusak")
		}
		return ed25519.PublicKey(pub), nil
	}
	return nil, ErrUnknownKey
}
