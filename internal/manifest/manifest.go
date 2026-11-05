// Package manifest defines the bundle manifest and detached signature formats.
package manifest

const (
	Version      = "1.1"
	AgentVersion = "1.0.0"
)

type Artifact struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	Redactions  int    `json:"redactions"`
	CollectedAt string `json:"collected_at"`
}

// CustodyEvent records node-side events only. They are self-reported by the node;
// later events (received, verified, reverified) live in the vault's hash-chained log.
type CustodyEvent struct {
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Note      string `json:"note"`
}

type Collector struct {
	AgentVersion string `json:"agent_version"`
	Mode         string `json:"mode"`
}

type Manifest struct {
	ManifestVersion  string         `json:"manifest_version"`
	BundleID         string         `json:"bundle_id"`
	NodeID           string         `json:"node_id"`
	Sequence         int64          `json:"sequence"`
	PrevBundleSHA256 *string        `json:"prev_bundle_sha256"`
	CollectedAt      string         `json:"collected_at"`
	TimeNote         string         `json:"time_note"`
	Collector        Collector      `json:"collector"`
	SignerKeyID      string         `json:"signer_key_id"`
	Trigger          string         `json:"trigger"`
	Artifacts        []Artifact     `json:"artifacts"`
	CustodyEvents    []CustodyEvent `json:"custody_events"`
}

// Signature is the content of manifest.sig. KeyID is only a hint used to look the
// public key up in the verifier's local trust store; the key itself is never shipped.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
