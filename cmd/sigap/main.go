// Command sigap is the single static binary used on edge nodes and analyst laptops:
// key generation, automatic detection + collection, and offline verification.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/bundle"
	"github.com/Daxxiee0x1/SIGAP/internal/collector"
	"github.com/Daxxiee0x1/SIGAP/internal/config"
	"github.com/Daxxiee0x1/SIGAP/internal/detector"
	"github.com/Daxxiee0x1/SIGAP/internal/manifest"
	"github.com/Daxxiee0x1/SIGAP/internal/signing"
	"github.com/Daxxiee0x1/SIGAP/internal/truststore"
	"github.com/Daxxiee0x1/SIGAP/internal/uplink"
	"github.com/Daxxiee0x1/SIGAP/internal/verify"
)

const usage = `SIGAP - forensik IoMT offline-first

Pemakaian:
  sigap keygen  --key-id ID --out node.key [--trust trust_store.json] [--valid-days 365]
  sigap collect --config agent.json [--trigger manual]
  sigap agent   --config agent.json
  sigap verify  --trust trust_store.json [--json] bundle.zip
  sigap version

Kode keluar verify: 0 VALID, 2 TAMPERED, 3 INCOMPLETE, 4 UNTRUSTED_SIGNER, 5 MALFORMED
`

func main() {
	log.SetFlags(0)
	log.SetPrefix("[sigap] ")
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "keygen":
		os.Exit(cmdKeygen(args))
	case "collect":
		os.Exit(cmdCollect(args))
	case "agent":
		os.Exit(cmdAgent(args))
	case "verify":
		os.Exit(cmdVerify(args))
	case "version":
		fmt.Println("sigap", manifest.AgentVersion)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(64)
	}
}

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	keyID := fs.String("key-id", "", "ID kunci, mis. node-sensor-01-2026-a")
	out := fs.String("out", "node.key", "lokasi berkas kunci privat (mode 0600)")
	trust := fs.String("trust", "", "trust_store.json yang ditambahi kunci publik (opsional)")
	days := fs.Int("valid-days", 365, "masa berlaku kunci (hari)")
	fs.Parse(args)
	if *keyID == "" {
		log.Print("--key-id wajib diisi")
		return 64
	}
	pub, kf, err := signing.Generate(*keyID)
	if err != nil {
		log.Print(err)
		return 1
	}
	if err := signing.Save(*out, kf); err != nil {
		log.Print(err)
		return 1
	}
	if *trust != "" {
		ts, err := truststore.LoadOrEmpty(*trust)
		if err != nil {
			log.Print(err)
			return 1
		}
		now := time.Now().UTC()
		ts.Upsert(truststore.Key{
			KeyID: *keyID, Algorithm: signing.Algorithm,
			PublicKey: base64.StdEncoding.EncodeToString(pub),
			NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, *days), Status: "active",
		})
		if err := ts.Save(*trust); err != nil {
			log.Print(err)
			return 1
		}
	}
	fmt.Printf("kunci %s dibuat: %s\n", *keyID, *out)
	return 0
}

func collectOnce(c *config.Agent, trigger string, alert *detector.Alert) error {
	priv, keyID, err := signing.Load(c.KeyFile)
	if err != nil {
		return fmt.Errorf("muat kunci: %w", err)
	}
	arts := collector.Collect(collector.Options{
		ProcRoot: c.ProcRoot, NodeID: c.NodeID, AgentVersion: manifest.AgentVersion,
		LogFiles: c.LogFiles, ConfigFiles: c.ConfigFiles, MaxLogBytes: c.MaxLogBytes,
	})
	if alert != nil {
		data, _ := json.MarshalIndent(alert, "", "  ")
		arts = append(arts, collector.Artifact{Name: "alert", File: "artifacts/alert.json", Data: data, CollectedAt: time.Now()})
	}
	st := bundle.LoadState(c.Outbox)
	opts := bundle.Options{NodeID: c.NodeID, KeyID: keyID, Priv: priv, Trigger: trigger, Sequence: st.Sequence + 1, PrevSHA: st.LastSHA}
	zipBytes, m, err := bundle.Pack(opts, arts, time.Now())
	if err != nil {
		return err
	}
	path, sum, err := bundle.Write(c.Outbox, zipBytes, m)
	if err != nil {
		return err
	}
	log.Printf("bundle %s: %d artefak, sha256 %s..., %s", m.BundleID, len(m.Artifacts), sum[:12], path)
	return nil
}

func cmdCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/sigap/agent.json", "konfigurasi agen")
	trigger := fs.String("trigger", "manual", "alasan koleksi (dicatat di manifest)")
	fs.Parse(args)
	c, err := config.Load(*cfgPath)
	if err != nil {
		log.Print(err)
		return 1
	}
	start := time.Now()
	if err := collectOnce(c, *trigger, nil); err != nil {
		log.Print(err)
		return 1
	}
	log.Printf("selesai dalam %s", time.Since(start).Round(time.Millisecond))
	return 0
}

// cmdAgent runs detector -> collector automatically (F-05), honours a manual trigger
// file, and flushes the outbox to the vault when a link exists.
func cmdAgent(args []string) int {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/sigap/agent.json", "konfigurasi agen")
	fs.Parse(args)
	c, err := config.Load(*cfgPath)
	if err != nil {
		log.Print(err)
		return 1
	}
	det, err := detector.New(c.Rules, c.ProcRoot)
	if err != nil {
		log.Print(err)
		return 1
	}
	token := ""
	if c.VaultTokenEnv != "" {
		token = os.Getenv(c.VaultTokenEnv)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(time.Duration(c.IntervalSeconds) * time.Second)
	defer tick.Stop()
	log.Printf("agen %s aktif, baseline diambil, interval %ds", c.NodeID, c.IntervalSeconds)

	// Uplink runs beside the detector so an unreachable vault never delays detection.
	var uplinking atomic.Bool
	lastUplinkErr := ""
	for {
		select {
		case <-stop:
			log.Print("berhenti")
			return 0
		case <-tick.C:
		}
		for _, a := range det.Check() {
			alert := a
			log.Printf("ALERT %s [%s] %s", alert.Rule, alert.Severity, alert.Detail)
			if err := collectOnce(c, "rule: "+alert.Rule, &alert); err != nil {
				log.Printf("koleksi gagal: %v", err)
			}
		}
		if c.TriggerFile != "" {
			if _, err := os.Stat(c.TriggerFile); err == nil {
				_ = os.Remove(c.TriggerFile)
				log.Print("trigger manual (berkas) diterima")
				if err := collectOnce(c, "manual-file", nil); err != nil {
					log.Printf("koleksi gagal: %v", err)
				}
			}
		}
		if c.VaultURL == "" {
			continue
		}
		if !uplinking.CompareAndSwap(false, true) {
			continue
		}
		go func() {
			defer uplinking.Store(false)
			n, err := uplink.Flush(c.Outbox, c.VaultURL, token, c.NodeID)
			switch {
			case err != nil && err.Error() != lastUplinkErr:
				lastUplinkErr = err.Error()
				log.Printf("uplink tertunda, bundle tetap di outbox: %v", err)
			case err == nil:
				if lastUplinkErr != "" {
					log.Print("link ke vault pulih")
				}
				lastUplinkErr = ""
				if n > 0 {
					log.Printf("uplink: %d bundle terkirim ke vault", n)
				}
			}
		}()
	}
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	trust := fs.String("trust", "trust_store.json", "trust store lokal")
	asJSON := fs.Bool("json", false, "keluaran JSON (dipakai vault)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		log.Print("pemakaian: sigap verify --trust trust_store.json [--json] bundle.zip")
		return 64
	}
	ts, err := truststore.Load(*trust)
	if err != nil {
		log.Print(err)
		return 5
	}
	start := time.Now()
	r := verify.VerifyFile(fs.Arg(0), ts, verify.DefaultLimits, time.Now())
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		fmt.Printf("%s  %s\n", r.Status, fs.Arg(0))
		for _, reason := range r.Reasons {
			fmt.Printf("  - %s\n", reason)
		}
		fmt.Printf("  sha256 bundle: %s\n  waktu: %s\n", r.BundleSHA256, time.Since(start).Round(time.Microsecond))
	}
	return r.Status.ExitCode()
}
