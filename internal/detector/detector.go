// Package detector evaluates explainable, rule-based anomaly checks on a node.
// Rules are the primary path; any ML experiment is reported separately.
package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Daxxiee0x1/SIGAP/internal/collector"
)

type Rules struct {
	ShellPatterns   []string `json:"shell_patterns"`
	EgressAllowlist []string `json:"egress_allowlist"`
	WatchedFiles    []string `json:"watched_files"`
	SuspiciousDirs  []string `json:"suspicious_exec_dirs"`
	CPUThresholdPct float64  `json:"cpu_threshold_pct"`
	MemThresholdPct float64  `json:"mem_threshold_pct"`
	SpikeSamples    int      `json:"spike_samples"`
	CooldownSeconds int      `json:"cooldown_seconds"`
}

type Alert struct {
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Detail   string    `json:"detail"`
	PID      int       `json:"pid,omitempty"`
	At       time.Time `json:"at"`
}

type Detector struct {
	rules     Rules
	procRoot  string
	allow     []*net.IPNet
	listen    map[int]bool
	hashes    map[string]string
	prevTotal uint64
	prevIdle  uint64
	spikeRun  int
	lastFired map[string]time.Time
	selfPID   int
}

// New captures the baseline (listening ports, watched file hashes, CPU counters).
func New(r Rules, procRoot string) (*Detector, error) {
	d := &Detector{
		rules: r, procRoot: procRoot,
		listen: map[int]bool{}, hashes: map[string]string{},
		lastFired: map[string]time.Time{}, selfPID: os.Getpid(),
	}
	for _, c := range r.EgressAllowlist {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("allowlist %q: %w", c, err)
		}
		d.allow = append(d.allow, n)
	}
	for _, c := range collector.ReadConns(procRoot) {
		if c.State == "LISTEN" {
			d.listen[c.LocalPort] = true
		}
	}
	for _, f := range r.WatchedFiles {
		d.hashes[f] = fileHash(f)
	}
	d.prevTotal, d.prevIdle = cpuTimes(procRoot)
	return d, nil
}

// Check evaluates every rule once. Repeated hits of the same rule+key are
// suppressed during the cooldown to keep the false-positive rate measurable.
func (d *Detector) Check() []Alert {
	now := time.Now()
	var alerts []Alert
	fire := func(rule, key, severity, detail string, pid int) {
		k := rule + "|" + key
		if t, ok := d.lastFired[k]; ok && now.Sub(t) < time.Duration(d.rules.CooldownSeconds)*time.Second {
			return
		}
		d.lastFired[k] = now
		alerts = append(alerts, Alert{Rule: rule, Severity: severity, Detail: detail, PID: pid, At: now})
	}

	for _, p := range collector.ReadProcesses(d.procRoot) {
		if p.PID == d.selfPID {
			continue
		}
		for _, pat := range d.rules.ShellPatterns {
			if pat != "" && strings.Contains(p.Cmdline, pat) {
				fire("reverse_shell_pattern", strconv.Itoa(p.PID), "critical",
					fmt.Sprintf("pid %d cocok pola %q: %s", p.PID, pat, p.Cmdline), p.PID)
				break
			}
		}
		for _, dir := range d.rules.SuspiciousDirs {
			if dir != "" && strings.HasPrefix(p.Exe, dir) {
				fire("exec_from_tmp", strconv.Itoa(p.PID), "high",
					fmt.Sprintf("pid %d berjalan dari %s", p.PID, p.Exe), p.PID)
				break
			}
		}
	}

	for _, c := range collector.ReadConns(d.procRoot) {
		switch c.State {
		case "LISTEN":
			if !d.listen[c.LocalPort] {
				fire("new_listen_port", strconv.Itoa(c.LocalPort), "medium",
					fmt.Sprintf("port listen baru %d (tidak ada di baseline)", c.LocalPort), 0)
			}
		case "ESTABLISHED", "SYN_SENT":
			if !c.RemoteIP.IsLoopback() && !d.allowed(c.RemoteIP) {
				fire("egress_outside_allowlist", fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort), "high",
					fmt.Sprintf("koneksi ke %s:%d di luar allowlist", c.RemoteIP, c.RemotePort), 0)
			}
		}
	}

	for f, base := range d.hashes {
		if h := fileHash(f); h != base {
			fire("watched_config_modified", f+"|"+h, "high",
				fmt.Sprintf("hash %s berubah: %s -> %s", f, short(base), short(h)), 0)
		}
	}

	if pct := d.cpuPct(); d.rules.CPUThresholdPct > 0 && pct >= d.rules.CPUThresholdPct {
		d.spikeRun++
		if d.spikeRun >= d.rules.SpikeSamples {
			fire("resource_spike", "cpu", "medium",
				fmt.Sprintf("CPU %.0f%% >= %.0f%% selama %d sampel", pct, d.rules.CPUThresholdPct, d.spikeRun), 0)
		}
	} else {
		d.spikeRun = 0
	}
	if mem := memUsedPct(d.procRoot); d.rules.MemThresholdPct > 0 && mem >= d.rules.MemThresholdPct {
		fire("resource_spike", "mem", "medium", fmt.Sprintf("memori %.0f%% >= %.0f%%", mem, d.rules.MemThresholdPct), 0)
	}
	return alerts
}

func (d *Detector) allowed(ip net.IP) bool {
	for _, n := range d.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (d *Detector) cpuPct() float64 {
	total, idle := cpuTimes(d.procRoot)
	if total <= d.prevTotal || idle < d.prevIdle {
		d.prevTotal, d.prevIdle = total, idle
		return 0
	}
	dt, di := total-d.prevTotal, idle-d.prevIdle
	d.prevTotal, d.prevIdle = total, idle
	return 100 * float64(dt-di) / float64(dt)
}

// cpuTimes reads the aggregate "cpu" line of /proc/stat.
func cpuTimes(procRoot string) (total, idle uint64) {
	data, err := os.ReadFile(procRoot + "/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(data), "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	for i, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	return total, idle
}

func memUsedPct(procRoot string) float64 {
	data, err := os.ReadFile(procRoot + "/meminfo")
	if err != nil {
		return 0
	}
	var total, avail float64
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total == 0 {
		return 0
	}
	return 100 * (total - avail) / total
}

func fileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "missing"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
