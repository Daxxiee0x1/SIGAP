// Package collector gathers lightweight live-response artifacts straight from /proc
// and files, with credential redaction. It never uses os/exec.
package collector

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

type Artifact struct {
	Name        string
	File        string // path inside the bundle, e.g. artifacts/process_list.txt
	Data        []byte
	Redactions  int
	CollectedAt time.Time
}

type Options struct {
	ProcRoot     string
	NodeID       string
	AgentVersion string
	LogFiles     []string
	ConfigFiles  []string
	MaxLogBytes  int64
}

func Collect(o Options) []Artifact {
	var arts []Artifact
	add := func(name, ext string, data []byte, redactions int) {
		arts = append(arts, Artifact{
			Name: name, File: "artifacts/" + name + "." + ext,
			Data: data, Redactions: redactions, CollectedAt: time.Now(),
		})
	}
	add("process_list", "txt", formatProcesses(ReadProcesses(o.ProcRoot)), 0)
	add("net_connections", "txt", formatConns(ReadConns(o.ProcRoot)), 0)
	logs, n := collectFiles(o.LogFiles, o.MaxLogBytes)
	add("system_log", "log", logs, n)
	cfg, n := collectFiles(o.ConfigFiles, 1<<20)
	add("config_redacted", "txt", cfg, n)
	add("node_meta", "json", nodeMeta(o), 0)
	return arts
}

func formatProcesses(ps []Process) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%-7s %-7s %-16s %-28s %s\n", "PID", "PPID", "COMM", "EXE", "CMDLINE")
	for _, p := range ps {
		fmt.Fprintf(&b, "%-7d %-7d %-16s %-28s %s\n", p.PID, p.PPID, p.Comm, p.Exe, p.Cmdline)
	}
	return []byte(b.String())
}

func formatConns(cs []Conn) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%-5s %-42s %-42s %s\n", "PROTO", "LOCAL", "REMOTE", "STATE")
	for _, c := range cs {
		local := fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort)
		remote := fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort)
		fmt.Fprintf(&b, "%-5s %-42s %-42s %s\n", c.Proto, local, remote, c.State)
	}
	return []byte(b.String())
}

var secretRE = regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)(\s*[:=]\s*)(\S+)`)

// Redact masks credential-looking values. The SHA-256 in the manifest is computed
// over the redacted bytes, and the redaction count is recorded per artifact.
func Redact(s string) (string, int) {
	n := len(secretRE.FindAllStringIndex(s, -1))
	return secretRE.ReplaceAllString(s, "${1}${2}[REDACTED]"), n
}

func collectFiles(paths []string, max int64) ([]byte, int) {
	var b strings.Builder
	for _, p := range paths {
		fmt.Fprintf(&b, "==> %s <==\n", p)
		data, err := tail(p, max)
		if err != nil {
			fmt.Fprintf(&b, "[tidak terbaca: %v]\n", err)
			continue
		}
		b.Write(data)
		b.WriteString("\n")
	}
	out, n := Redact(b.String())
	return []byte(out), n
}

// tail reads at most max bytes from the end of a file.
func tail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, max))
}

func nodeMeta(o Options) []byte {
	host, _ := os.Hostname()
	meta := map[string]any{
		"node_id":       o.NodeID,
		"hostname":      host,
		"agent_version": o.AgentVersion,
		"kernel":        readTrim(o.ProcRoot + "/sys/kernel/osrelease"),
		"uptime":        readTrim(o.ProcRoot + "/uptime"),
		"collected_at":  time.Now().Format(time.RFC3339),
		"time_note":     "self-reported by node",
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	return data
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
