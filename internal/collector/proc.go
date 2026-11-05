package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Process struct {
	PID     int
	PPID    int
	Comm    string
	Cmdline string
	Exe     string
}

// ReadProcesses walks /proc directly. It never shells out to ps, so a replaced
// ps binary cannot hide processes (a kernel rootkit still can; see threat model).
func ReadProcesses(procRoot string) []Process {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		p := Process{PID: pid}
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			p.Comm = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		}
		if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
			p.Exe = exe
		}
		if b, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
			p.PPID = parsePPID(string(b))
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// parsePPID reads "pid (comm) state ppid ..."; comm may itself contain spaces or ")".
func parsePPID(stat string) int {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(stat[i+1:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

type Conn struct {
	Proto      string
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"06": "TIME_WAIT", "08": "CLOSE_WAIT", "0A": "LISTEN",
}

// ReadConns parses /proc/net/tcp and /proc/net/tcp6 without calling ss/netstat.
func ReadConns(procRoot string) []Conn {
	var out []Conn
	for _, proto := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procRoot, "net", proto))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header line
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			lip, lport, err1 := parseAddr(fields[1])
			rip, rport, err2 := parseAddr(fields[2])
			if err1 != nil || err2 != nil {
				continue
			}
			state, ok := tcpStates[fields[3]]
			if !ok {
				state = "0x" + fields[3]
			}
			out = append(out, Conn{proto, lip, lport, rip, rport, state})
		}
		f.Close()
	}
	return out
}

func parseAddr(s string) (net.IP, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("alamat tidak valid %q", s)
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	b, err := hex.DecodeString(host)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, 0, fmt.Errorf("host tidak valid %q", host)
	}
	// The kernel prints each 32-bit word in little-endian byte order.
	ip := make(net.IP, len(b))
	for i := 0; i+3 < len(b); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return ip, int(p), nil
}
