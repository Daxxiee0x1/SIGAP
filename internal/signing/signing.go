// Package signing creates and loads Ed25519 node keys and detached manifest signatures.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Daxxiee0x1/SIGAP/internal/manifest"
)

const Algorithm = "ed25519"

// KeyFile is the on-disk private key format. It is written with mode 0600.
type KeyFile struct {
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"private_key"` // base64 32-byte seed
}

func Generate(keyID string) (ed25519.PublicKey, KeyFile, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, KeyFile{}, err
	}
	kf := KeyFile{KeyID: keyID, Algorithm: Algorithm, PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed())}
	return pub, kf, nil
}

func Save(path string, kf KeyFile) error {
	data, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Parse turns a KeyFile into a usable private key.
func Parse(kf KeyFile) (ed25519.PrivateKey, error) {
	if kf.Algorithm != Algorithm {
		return nil, fmt.Errorf("algoritma tidak didukung: %q", kf.Algorithm)
	}
	seed, err := base64.StdEncoding.DecodeString(kf.PrivateKey)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed kunci privat tidak valid")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func Load(path string) (ed25519.PrivateKey, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, "", fmt.Errorf("parse berkas kunci: %w", err)
	}
	priv, err := Parse(kf)
	if err != nil {
		return nil, "", err
	}
	return priv, kf.KeyID, nil
}

// Sign returns the content of manifest.sig: a detached signature over the exact
// bytes of manifest.json. Nothing inside the manifest refers to its own signature.
func Sign(priv ed25519.PrivateKey, keyID string, manifestBytes []byte) ([]byte, error) {
	sig := manifest.Signature{
		Algorithm: Algorithm,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifestBytes)),
	}
	return json.MarshalIndent(sig, "", "  ")
}
