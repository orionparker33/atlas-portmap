// Package localarp reads the operating system's ARP / IPv6 neighbour cache, for networks where
// no router answers SNMP. Only hosts this machine has talked to are listed.
package localarp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/macaddr"
)

// Source names local-cache entries.
const Source = collect.LocalSource

// Read returns the local neighbour cache.
func Read(ctx context.Context) ([]collect.ARPEntry, error) {
	switch runtime.GOOS {
	case "linux":
		if out, err := exec.CommandContext(ctx, "ip", "neigh", "show").Output(); err == nil {
			return finish(ParseIPNeigh(string(out))), nil
		}
		b, err := os.ReadFile("/proc/net/arp")
		if err != nil {
			return nil, fmt.Errorf("local ARP: %w", err)
		}
		return finish(ParseProcARP(string(b))), nil
	case "windows":
		out, err := exec.CommandContext(ctx, "arp", "-a").Output()
		if err != nil {
			return nil, fmt.Errorf("local ARP (arp -a): %w", err)
		}
		return finish(ParseWindowsARP(string(out))), nil
	default:
		out, err := exec.CommandContext(ctx, "arp", "-an").Output()
		if err != nil {
			return nil, fmt.Errorf("local ARP (arp -an): %w", err)
		}
		return finish(ParseBSDARP(string(out))), nil
	}
}

func finish(e []collect.ARPEntry) []collect.ARPEntry {
	collect.SortARP(e)
	return e
}

func entry(ip, mac, iface string) (collect.ARPEntry, bool) {
	a := net.ParseIP(ip)
	m, err := macaddr.Parse(mac)
	if a == nil || err != nil || !macaddr.Usable(m) || a.IsMulticast() || a.IsUnspecified() {
		return collect.ARPEntry{}, false
	}
	return collect.ARPEntry{IP: a, MAC: m, Iface: iface, Source: Source}, true
}

// OwnMACs maps this machine's interface names, and each of their addresses, to the interface's
// MAC, so an entry's Iface (an interface name, or on Windows the interface's address) finds the
// MAC this machine uses on that segment.
func OwnMACs() map[string]net.HardwareAddr {
	out := map[string]net.HardwareAddr{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, f := range ifs {
		if len(f.HardwareAddr) != 6 || f.Flags&net.FlagLoopback != 0 {
			continue
		}
		out[f.Name] = f.HardwareAddr
		if addrs, err := f.Addrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok {
					out[n.IP.String()] = f.HardwareAddr
				}
			}
		}
	}
	return out
}

// ParseIPNeigh parses `ip neigh show`: "10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE".
func ParseIPNeigh(s string) []collect.ARPEntry {
	var out []collect.ARPEntry
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		switch f[len(f)-1] {
		case "FAILED", "INCOMPLETE":
			continue
		}
		dev := ""
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "dev" {
				dev = f[i+1]
			}
		}
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				if e, ok := entry(f[0], f[i+1], dev); ok {
					out = append(out, e)
				}
				break
			}
		}
	}
	return out
}

// ParseProcARP parses /proc/net/arp (IP, HW type, flags, HW address, mask, device); flags 0x0
// mark incomplete entries.
func ParseProcARP(s string) []collect.ARPEntry {
	var out []collect.ARPEntry
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[0] == "IP" || f[2] == "0x0" {
			continue
		}
		if e, ok := entry(f[0], f[3], f[5]); ok {
			out = append(out, e)
		}
	}
	return out
}

var (
	winARP   = regexp.MustCompile(`^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s`)
	winIface = regexp.MustCompile(`^\S.*?:\s*(\d{1,3}(?:\.\d{1,3}){3})\s+---\s+0x[0-9A-Fa-f]+`)
)

// ParseWindowsARP parses `arp -a` on Windows: an "Interface: 10.0.0.5 --- 0x5" header (its label
// is localised) then rows ("  10.0.0.1   00-11-22-33-44-55   dynamic"). Each entry's Iface is
// the interface address from its header. The type column is localised too, so only the address
// columns are used.
func ParseWindowsARP(s string) []collect.ARPEntry {
	var out []collect.ARPEntry
	iface := ""
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if m := winIface.FindStringSubmatch(sc.Text()); m != nil {
			iface = m[1]
			continue
		}
		if m := winARP.FindStringSubmatch(sc.Text() + " "); m != nil {
			if e, ok := entry(m[1], m[2], iface); ok {
				out = append(out, e)
			}
		}
	}
	return out
}

var bsdARP = regexp.MustCompile(`\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5})\b(?:.*? on (\S+))?`)

// ParseBSDARP parses `arp -an` on macOS/BSD ("? (10.0.0.1) at 0:11:22:3:44:55 on en0 …").
func ParseBSDARP(s string) []collect.ARPEntry {
	var out []collect.ARPEntry
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if m := bsdARP.FindStringSubmatch(sc.Text()); m != nil {
			if e, ok := entry(m[1], m[2], m[3]); ok {
				out = append(out, e)
			}
		}
	}
	return out
}
