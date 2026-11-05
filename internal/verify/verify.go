// Package verify checks a bundle offline against a local trust store.
// Bundles are treated as untrusted input from the first byte.
package verify

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/manifest"
	"github.com/Daxxiee0x1/SIGAP/internal/truststore"
)

type Status string

const (
	Valid           Status = "VALID"
	Tampered        Status = "TAMPERED"
	Incomplete      Status = "INCOMPLETE"
	UntrustedSigner Status = "UNTRUSTED_SIGNER"
	Malformed       Status = "MALFORMED"
)

// ExitCode lets shell scripts and the Python vault branch on the result.
func (s Status) ExitCode() int {
	switch s {
	case Valid:
		return 0
	case Tampered:
		return 2
	case Incomplete:
		return 3
	case UntrustedSigner:
		return 4
	default:
		return 5
	}
}

type Limits struct {
	MaxBundleBytes  int64
	MaxFiles        int
	MaxUncompressed uint64
	MaxRatio        uint64 // applied once the uncompressed total exceeds 1 MiB
}

// DefaultLimits are initial proposals (PRD section 7), to be tuned during testing.
var DefaultLimits = Limits{MaxBundleBytes: 20 << 20, MaxFiles: 50, MaxUncompressed: 100 << 20, MaxRatio: 10}

type Result struct {
	Status       Status             `json:"status"`
	Reasons      []string           `json:"reasons"`
	BundleSHA256 string             `json:"bundle_sha256"`
	KeyID        string             `json:"key_id,omitempty"`
	Manifest     *manifest.Manifest `json:"manifest,omitempty"`
}

var nameRE = regexp.MustCompile(`^(manifest\.json|manifest\.sig|artifacts/[a-z0-9_]{1,64}\.(txt|json|log))$`)

func VerifyFile(path string, ts *truststore.Store, lim Limits, now time.Time) *Result {
	f, err := os.Open(path)
	if err != nil {
		return &Result{Status: Malformed, Reasons: []string{err.Error()}}
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, lim.MaxBundleBytes+1))
	if err != nil {
		return &Result{Status: Malformed, Reasons: []string{err.Error()}}
	}
	return VerifyBytes(raw, ts, lim, now)
}

func VerifyBytes(raw []byte, ts *truststore.Store, lim Limits, now time.Time) *Result {
	sum := sha256.Sum256(raw)
	r := &Result{Reasons: []string{}, BundleSHA256: hex.EncodeToString(sum[:])}
	reject := func(s Status, format string, a ...any) *Result {
		r.Status = s
		r.Reasons = append(r.Reasons, fmt.Sprintf(format, a...))
		return r
	}
	entryErr := func(err error) *Result {
		if errors.Is(err, zip.ErrChecksum) {
			return reject(Tampered, "checksum entri zip rusak: %v", err)
		}
		return reject(Malformed, "%v", err)
	}

	// 1. Structural limits before any entry is read: size, count, names, symlinks, bombs.
	if int64(len(raw)) > lim.MaxBundleBytes {
		return reject(Malformed, "bundle melebihi %d byte", lim.MaxBundleBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return reject(Malformed, "bukan arsip zip yang valid: %v", err)
	}
	if len(zr.File) > lim.MaxFiles {
		return reject(Malformed, "jumlah berkas %d melebihi batas %d", len(zr.File), lim.MaxFiles)
	}
	files := make(map[string]*zip.File, len(zr.File))
	var total uint64
	for _, f := range zr.File {
		if !nameRE.MatchString(f.Name) {
			return reject(Malformed, "nama berkas ditolak: %q", f.Name)
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return reject(Malformed, "symlink tidak diizinkan: %q", f.Name)
		}
		if _, dup := files[f.Name]; dup {
			return reject(Malformed, "entri ganda: %q", f.Name)
		}
		files[f.Name] = f
		total += f.UncompressedSize64
	}
	if total > lim.MaxUncompressed || (total > 1<<20 && total > uint64(len(raw))*lim.MaxRatio) {
		return reject(Malformed, "ukuran terdekompresi %d byte melebihi batas (indikasi bom dekompresi)", total)
	}

	mf, okM := files["manifest.json"]
	sf, okS := files["manifest.sig"]
	if !okM || !okS {
		return reject(Malformed, "manifest.json atau manifest.sig tidak ada")
	}
	mBytes, err := readEntry(mf, 1<<20)
	if err != nil {
		return entryErr(err)
	}
	sBytes, err := readEntry(sf, 16<<10)
	if err != nil {
		return entryErr(err)
	}
	var sig manifest.Signature
	if err := json.Unmarshal(sBytes, &sig); err != nil || sig.Algorithm != "ed25519" || sig.KeyID == "" {
		return reject(Malformed, "manifest.sig tidak valid")
	}
	r.KeyID = sig.KeyID

	// 2. The public key comes ONLY from the local trust store, never from the bundle.
	pub, err := ts.Lookup(sig.KeyID, now)
	if err != nil {
		return reject(UntrustedSigner, "penanda tangan %q: %v", sig.KeyID, err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return reject(Tampered, "nilai tanda tangan rusak")
	}

	// 3. Verify the signature over the raw manifest bytes BEFORE parsing them.
	if !ed25519.Verify(pub, mBytes, sigBytes) {
		return reject(Tampered, "tanda tangan tidak cocok dengan byte manifest.json")
	}
	var m manifest.Manifest
	dec := json.NewDecoder(bytes.NewReader(mBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return reject(Malformed, "manifest tidak dapat di-parse: %v", err)
	}
	r.Manifest = &m
	if m.SignerKeyID != sig.KeyID {
		return reject(Tampered, "signer_key_id manifest %q berbeda dengan manifest.sig %q", m.SignerKeyID, sig.KeyID)
	}

	// 4. Zip contents must equal: manifest list + manifest.json + manifest.sig.
	listed := map[string]bool{"manifest.json": true, "manifest.sig": true}
	var tampered, missing []string
	budget := lim.MaxUncompressed
	for _, a := range m.Artifacts {
		listed[a.Path] = true
		f, ok := files[a.Path]
		if !ok {
			missing = append(missing, a.Path)
			continue
		}
		data, err := readEntry(f, int64(budget))
		if err != nil {
			return entryErr(err)
		}
		budget -= uint64(len(data))
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != a.SHA256 || int64(len(data)) != a.SizeBytes {
			tampered = append(tampered, "hash/ukuran tidak cocok: "+a.Path)
		}
	}
	for name := range files {
		if !listed[name] {
			tampered = append(tampered, "berkas tidak terdaftar di manifest: "+name)
		}
	}
	sort.Strings(tampered)
	switch {
	case len(tampered) > 0:
		r.Status = Tampered
		r.Reasons = append(r.Reasons, tampered...)
	case len(missing) > 0:
		r.Status = Incomplete
		for _, p := range missing {
			r.Reasons = append(r.Reasons, "berkas di manifest tidak ada di zip: "+p)
		}
	default:
		r.Status = Valid
		r.Reasons = append(r.Reasons, fmt.Sprintf("tanda tangan sah (%s); %d artefak cocok", sig.KeyID, len(m.Artifacts)))
	}
	return r
}

func readEntry(f *zip.File, max int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("entri %s melebihi batas %d byte", f.Name, max)
	}
	return data, nil
}
