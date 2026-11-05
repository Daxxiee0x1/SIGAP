package playground

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/bundle"
	"github.com/Daxxiee0x1/SIGAP/internal/collector"
	"github.com/Daxxiee0x1/SIGAP/internal/signing"
	"github.com/Daxxiee0x1/SIGAP/internal/truststore"
	"github.com/Daxxiee0x1/SIGAP/internal/verify"
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

func TestEditThenVerify(t *testing.T) {
	raw, ts := fixture(t)
	cases := []struct {
		name, op, entry, content string
		want                     verify.Status
	}{
		{"isi sama tetap sah", "replace", "artifacts/system_log.log", "boot ok\n", verify.Valid},
		{"ubah satu karakter", "replace", "artifacts/process_list.txt", "PID CMD\n1 inix\n", verify.Tampered},
		{"hapus artefak", "remove", "artifacts/system_log.log", "", verify.Incomplete},
		{"tambah berkas", "add", "artifacts/extra.txt", "x", verify.Tampered},
		{"ubah manifest", "replace", "manifest.json", "{}", verify.Tampered},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			edited, err := Edit(raw, c.op, c.entry, []byte(c.content))
			if err != nil {
				t.Fatal(err)
			}
			if got := verify.VerifyBytes(edited, ts, verify.DefaultLimits, now).Status; got != c.want {
				t.Fatalf("status %s, harus %s", got, c.want)
			}
		})
	}
}

func TestEditErrors(t *testing.T) {
	raw, _ := fixture(t)
	if _, err := Edit(raw, "replace", "artifacts/tidak_ada.txt", nil); err == nil {
		t.Fatal("mengubah berkas yang tidak ada harus gagal")
	}
	if _, err := Edit(raw, "add", "manifest.json", nil); err == nil {
		t.Fatal("menambah berkas yang sudah ada harus gagal")
	}
	if _, err := Edit([]byte("bukan zip"), "remove", "x", nil); err == nil {
		t.Fatal("input bukan zip harus gagal")
	}
}

func TestEntries(t *testing.T) {
	raw, _ := fixture(t)
	es, err := Entries(raw)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Entry{}
	for _, e := range es {
		byName[e.Name] = e
	}
	if byName["artifacts/system_log.log"].Text != "boot ok\n" {
		t.Fatalf("isi system_log tidak terbaca: %+v", byName["artifacts/system_log.log"])
	}
	if _, ok := byName["manifest.json"]; !ok {
		t.Fatal("manifest.json tidak terdaftar")
	}
}
