// Package bundle builds signed evidence bundles and tracks node sequence state.
package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/collector"
	"github.com/Daxxiee0x1/SIGAP/internal/manifest"
	"github.com/Daxxiee0x1/SIGAP/internal/signing"
)

type Options struct {
	NodeID   string
	KeyID    string
	Priv     ed25519.PrivateKey
	Trigger  string
	Sequence int64
	PrevSHA  *string
}

// Pack writes manifest.json, signs its exact bytes into manifest.sig, and zips both
// with the artifacts. The zip contains nothing else.
func Pack(o Options, arts []collector.Artifact, now time.Time) ([]byte, manifest.Manifest, error) {
	ts := now.Format(time.RFC3339)
	m := manifest.Manifest{
		ManifestVersion:  manifest.Version,
		BundleID:         fmt.Sprintf("bnd-%s-%s-%03d", o.NodeID, now.Format("20060102"), o.Sequence),
		NodeID:           o.NodeID,
		Sequence:         o.Sequence,
		PrevBundleSHA256: o.PrevSHA,
		CollectedAt:      ts,
		TimeNote:         "self-reported by node",
		Collector:        manifest.Collector{AgentVersion: manifest.AgentVersion, Mode: "proc-direct"},
		SignerKeyID:      o.KeyID,
		Trigger:          o.Trigger,
		Artifacts:        []manifest.Artifact{},
		CustodyEvents: []manifest.CustodyEvent{
			{Action: "collected", Timestamp: ts, Actor: "sigap-agent", Note: o.Trigger},
		},
	}
	for _, a := range arts {
		sum := sha256.Sum256(a.Data)
		m.Artifacts = append(m.Artifacts, manifest.Artifact{
			Name: a.Name, Path: a.File, SHA256: hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(a.Data)), Redactions: a.Redactions,
			CollectedAt: a.CollectedAt.Format(time.RFC3339),
		})
	}
	m.CustodyEvents = append(m.CustodyEvents, manifest.CustodyEvent{
		Action: "packaged", Timestamp: time.Now().Format(time.RFC3339),
		Actor: "sigap-agent", Note: fmt.Sprintf("%d artefak", len(arts)),
	})

	mBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, m, err
	}
	sigBytes, err := signing.Sign(o.Priv, o.KeyID, mBytes)
	if err != nil {
		return nil, m, err
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	if err := write("manifest.json", mBytes); err != nil {
		return nil, m, err
	}
	if err := write("manifest.sig", sigBytes); err != nil {
		return nil, m, err
	}
	for _, a := range arts {
		if err := write(a.File, a.Data); err != nil {
			return nil, m, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, m, err
	}
	return buf.Bytes(), m, nil
}

// State lets the next bundle reference the previous one (sequence + hash), making
// gaps or naive reordering visible. A compromised node can rewrite this.
type State struct {
	Sequence int64   `json:"sequence"`
	LastSHA  *string `json:"last_bundle_sha256"`
}

func LoadState(dir string) State {
	var s State
	if data, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

// Write stores the bundle in the outbox and advances the node state.
func Write(dir string, zipBytes []byte, m manifest.Manifest) (path, sum string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	h := sha256.Sum256(zipBytes)
	sum = hex.EncodeToString(h[:])
	path = filepath.Join(dir, m.BundleID+".zip")
	if _, err := os.Stat(path); err == nil {
		return "", "", errors.New("bundle sudah ada: " + path)
	}
	// Write to a temp name and rename, so the uplink never ships a half-written zip.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, zipBytes, 0o600); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", "", err
	}
	st, _ := json.MarshalIndent(State{Sequence: m.Sequence, LastSHA: &sum}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "state.json"), st, 0o600); err != nil {
		return "", "", err
	}
	return path, sum, nil
}
