package verify

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/bundle"
	"github.com/Daxxiee0x1/SIGAP/internal/collector"
	"github.com/Daxxiee0x1/SIGAP/internal/signing"
	"github.com/Daxxiee0x1/SIGAP/internal/truststore"
)

var now = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func fixture(t *testing.T) ([]byte, *truststore.Store) {
	t.Helper()
	pub, kf, err := signing.Generate("node-test-a")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := signing.Parse(kf)
	if err != nil {
		t.Fatal(err)
	}
	ts := &truststore.Store{Version: 1, Keys: []truststore.Key{{
		KeyID: "node-test-a", Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), Status: "active",
	}}}
	arts := []collector.Artifact{
		{Name: "process_list", File: "artifacts/process_list.txt", Data: []byte("PID CMD\n1 init\n"), CollectedAt: now},
		{Name: "system_log", File: "artifacts/system_log.log", Data: []byte("boot ok\n"), CollectedAt: now},
	}
	raw, _, err := bundle.Pack(bundle.Options{NodeID: "sensor-test", KeyID: "node-test-a", Priv: priv, Trigger: "test", Sequence: 1}, arts, now)
	if err != nil {
		t.Fatal(err)
	}
	return raw, ts
}

type editFn func(name string, data []byte) ([]byte, bool)

func keepAll(_ string, d []byte) ([]byte, bool) { return d, true }

// rewrite re-zips a bundle (recomputing CRCs, as a careful attacker would).
func rewrite(t *testing.T, raw []byte, edit editFn, extra map[string][]byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		data, keep := edit(f.Name, data)
		if !keep {
			continue
		}
		w, _ := zw.Create(f.Name)
		w.Write(data)
	}
	for name, data := range extra {
		w, _ := zw.Create(name)
		w.Write(data)
	}
	zw.Close()
	return buf.Bytes()
}

func TestVerify(t *testing.T) {
	raw, ts := fixture(t)
	cases := []struct {
		name   string
		bundle []byte
		want   Status
	}{
		{"valid", raw, Valid},
		{"artifact byte flipped", rewrite(t, raw, func(n string, d []byte) ([]byte, bool) {
			if n == "artifacts/process_list.txt" {
				d[0] ^= 0x01
			}
			return d, true
		}, nil), Tampered},
		{"unlisted file added", rewrite(t, raw, keepAll, map[string][]byte{"artifacts/extra.txt": []byte("x")}), Tampered},
		{"listed file removed", rewrite(t, raw, func(n string, d []byte) ([]byte, bool) {
			return d, n != "artifacts/system_log.log"
		}, nil), Incomplete},
		{"manifest edited", rewrite(t, raw, func(n string, d []byte) ([]byte, bool) {
			if n == "manifest.json" {
				d = bytes.Replace(d, []byte("sensor-test"), []byte("sensor-evil"), 1)
			}
			return d, true
		}, nil), Tampered},
		{"zip slip name", rewrite(t, raw, keepAll, map[string][]byte{"../../etc/cron.d/x": []byte("x")}), Malformed},
		{"not a zip", []byte("hello"), Malformed},
	}
	for _, c := range cases {
		if got := VerifyBytes(c.bundle, ts, DefaultLimits, now); got.Status != c.want {
			t.Errorf("%s: got %s %v, want %s", c.name, got.Status, got.Reasons, c.want)
		}
	}

	if got := VerifyBytes(raw, &truststore.Store{}, DefaultLimits, now); got.Status != UntrustedSigner {
		t.Errorf("unknown key: got %s", got.Status)
	}
	ts.Keys[0].Status = "revoked"
	if got := VerifyBytes(raw, ts, DefaultLimits, now); got.Status != UntrustedSigner {
		t.Errorf("revoked key: got %s", got.Status)
	}
}
