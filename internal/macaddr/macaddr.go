// Package macaddr parses and formats EUI-48 MAC addresses in the notations switches and
// operating systems print them in.
package macaddr

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Parse accepts aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff, aabbccddeeff,
// "aa bb cc dd ee ff" and unpadded octets such as 0:1b:63:a:b:c (BSD arp). Only 6-octet
// addresses are accepted.
func Parse(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty MAC address")
	}
	for _, sep := range []string{":", "-", " "} {
		if !strings.Contains(s, sep) {
			continue
		}
		parts := strings.Fields(strings.ReplaceAll(s, sep, " "))
		if len(parts) != 6 {
			return nil, fmt.Errorf("unrecognised MAC address %q", s)
		}
		b := make(net.HardwareAddr, 6)
		for i, p := range parts {
			if len(p) > 2 {
				return nil, fmt.Errorf("bad MAC octet %q in %q", p, s)
			}
			v, err := strconv.ParseUint(p, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("bad MAC octet %q in %q", p, s)
			}
			b[i] = byte(v)
		}
		return b, nil
	}
	h := s
	if strings.Contains(s, ".") { // Cisco dotted: exactly three groups of four hex digits
		parts := strings.Split(s, ".")
		if len(parts) != 3 || len(parts[0]) != 4 || len(parts[1]) != 4 || len(parts[2]) != 4 {
			return nil, fmt.Errorf("unrecognised MAC address %q", s)
		}
		h = strings.Join(parts, "")
	}
	if len(h) == 12 {
		if b, err := hex.DecodeString(h); err == nil {
			return net.HardwareAddr(b), nil
		}
	}
	return nil, fmt.Errorf("unrecognised MAC address %q", s)
}

// Styles accepted by Format.
var Styles = []string{"colon", "dash", "dot", "bare"}

// Format renders mac as colon (aa:bb:cc:dd:ee:ff, the default), dash (AA-BB-CC-DD-EE-FF),
// dot (aabb.ccdd.eeff, Cisco) or bare (aabbccddeeff).
func Format(mac net.HardwareAddr, style string) string {
	h := hex.EncodeToString(mac)
	switch style {
	case "dash":
		return strings.ToUpper(group(h, "-", 2))
	case "dot":
		return group(h, ".", 4)
	case "bare":
		return h
	default:
		return group(h, ":", 2)
	}
}

func group(h, sep string, n int) string {
	var b strings.Builder
	for i := 0; i < len(h); i += n {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(h[i:min(i+n, len(h))])
	}
	return b.String()
}

// Usable reports whether mac is a unicast EUI-48 address worth mapping: six octets, not
// all-zero and not a group (multicast or broadcast) address.
func Usable(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&0x01 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}

// LocallyAdministered reports the U/L bit: randomised client MACs, VMs and containers.
func LocallyAdministered(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}
