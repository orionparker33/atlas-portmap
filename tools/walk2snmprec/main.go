// Command walk2snmprec turns `atlas-portmap walk` output captured from a real device into an
// snmpsim .snmprec file, so the device's real tables can serve as a regression fixture.
//
//	go run ./tools/walk2snmprec -anon walk1.txt walk2.txt > e2e/testdata/device.snmprec
//
// With -anon every MAC address keeps its OUI but gets random NIC bytes (fresh each run, never
// recorded, so the mapping cannot be reversed), consistently everywhere it appears: 6-byte OCTET
// STRING values, BRIDGE-MIB / Q-BRIDGE FDB indexes, STP bridge IDs, EUI-64 and solicited-node
// IPv6 addresses in indexes, and the NIC hex in text values (a default sysName such as
// "switch0a1b2c" follows its bridge address). Group and multicast addresses are kept. Hardware
// serial numbers (ENTITY-MIB, LLDP-MED) become zeros everywhere, and sysContact and sysLocation
// are blanked. Check the result for names, aliases and addresses you do not want to publish.
// Walk output is lossy in two ways the fixture inherits: text values are trimmed, and a binary
// value whose bytes all happen to be printable is indistinguishable from text.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	line   = regexp.MustCompile(`^([0-9.]+) = ([A-Za-z0-9]+): ?(.*)$`)
	hexVal = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2})+$`)
	tags   = map[string]string{"INTEGER": "2", "OID": "6", "IpAddress": "64", "Counter32": "65",
		"Gauge32": "66", "Timeticks": "67", "Counter64": "70"}
	// FDB tables whose index ends in a MAC address.
	fdbPrefixes = [][]uint32{
		{1, 3, 6, 1, 2, 1, 17, 4, 3, 1},       // dot1dTpFdbEntry: .col.mac
		{1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1}, // dot1qTpFdbEntry: .col.fdbId.mac
	}
)

type rec struct {
	oid      []uint32
	tag, val string
}

func main() {
	anon := flag.Bool("anon", false, "replace MAC NIC bytes (OUIs are kept) and serial numbers, blank sysContact/sysLocation")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: walk2snmprec [-anon] walk.txt...")
		os.Exit(2)
	}
	var recs []rec
	seen := map[string]bool{}
	for _, path := range flag.Args() {
		f, err := os.Open(path)
		if err != nil {
			fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for n := 1; sc.Scan(); n++ {
			m := line.FindStringSubmatch(sc.Text())
			if m == nil {
				fatal(fmt.Errorf("%s:%d: not a walk line", path, n))
			}
			if seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			oid, err := parseOID(m[1])
			if err != nil {
				fatal(fmt.Errorf("%s:%d: %v", path, n, err))
			}
			r := rec{oid: oid}
			switch t := m[2]; {
			case t == "STRING" && hexVal.MatchString(m[3]):
				r.tag, r.val = "4x", strings.ReplaceAll(m[3], ":", "")
			case t == "STRING" && (strings.ContainsAny(m[3], "|\r\n") || !ascii(m[3])):
				r.tag, r.val = "4x", hex.EncodeToString([]byte(m[3]))
			case t == "STRING":
				r.tag, r.val = "4", m[3]
			case tags[t] != "":
				r.tag, r.val = tags[t], m[3]
			default:
				fatal(fmt.Errorf("%s:%d: unknown type %s", path, n, t))
			}
			recs = append(recs, r)
		}
		f.Close()
		if err := sc.Err(); err != nil {
			fatal(err)
		}
	}
	if *anon {
		anonymize(recs)
		scrubSerials(recs)
	}
	sort.Slice(recs, func(i, j int) bool { return less(recs[i].oid, recs[j].oid) })
	w := bufio.NewWriter(os.Stdout)
	for _, r := range recs {
		fmt.Fprintf(w, "%s|%s|%s\n", oidString(r.oid), r.tag, r.val)
	}
	if err := w.Flush(); err != nil {
		fatal(err)
	}
}

// anonymize remaps unicast MACs found in 6-byte values and FDB indexes, then rewrites them
// everywhere, including the NIC hex digits inside text values.
func anonymize(recs []rec) {
	remap := map[string]string{} // 12 lowercase hex digits -> replacement
	used := map[string]bool{}
	add := func(h string) {
		if len(h) != 12 || remap[h] != "" {
			return
		}
		b, _ := hex.DecodeString(h)
		if b[0]&1 == 1 || h == "000000000000" { // group address or zero: not a device
			return
		}
		for {
			var nic [3]byte
			if _, err := rand.Read(nic[:]); err != nil {
				fatal(err)
			}
			if n := h[:6] + hex.EncodeToString(nic[:]); n != h && !used[n] {
				used[n], remap[h] = true, n
				return
			}
		}
	}
	for _, r := range recs {
		if r.tag == "4x" && len(r.val) == 12 {
			add(r.val)
		}
		if i := fdbMAC(r.oid); i >= 0 {
			add(macHex(r.oid[i:]))
		}
	}
	nics := map[[3]uint32][3]uint32{} // NIC bytes as OID arcs, for IPv6 addresses in indexes
	for old, n := range remap {
		o, _ := hex.DecodeString(old[6:])
		w, _ := hex.DecodeString(n[6:])
		nics[[3]uint32{uint32(o[0]), uint32(o[1]), uint32(o[2])}] = [3]uint32{uint32(w[0]), uint32(w[1]), uint32(w[2])}
	}
	for k := range recs {
		r := &recs[k]
		// IPv6 addresses in indexes (IP-MIB ipAddressTable): EUI-64 ...ff:fe:NIC and the
		// solicited-node group ff02::1:ff:NIC.
		for i := 0; i+5 <= len(r.oid); i++ {
			if (r.oid[i] == 255 && r.oid[i+1] == 254) || (r.oid[i] == 1 && r.oid[i+1] == 255) {
				if n, ok := nics[[3]uint32{r.oid[i+2], r.oid[i+3], r.oid[i+4]}]; ok {
					copy(r.oid[i+2:i+5], n[:])
				}
			}
		}
		if i := fdbMAC(r.oid); i >= 0 {
			if n, ok := remap[macHex(r.oid[i:])]; ok {
				b, _ := hex.DecodeString(n)
				for j, x := range b {
					r.oid[i+j] = uint32(x)
				}
			}
		}
		switch r.tag {
		case "4x":
			if n, ok := remap[r.val]; ok {
				r.val = n
				continue
			}
			// Embedded forms: STP bridge IDs (priority + MAC) and EUI-64 interface IDs.
			for old, n := range remap {
				r.val = strings.ReplaceAll(r.val, old, n)
				r.val = strings.ReplaceAll(r.val, eui64(old), eui64(n))
			}
		case "4":
			for old, n := range remap {
				r.val = strings.ReplaceAll(r.val, old[6:], n[6:])
				r.val = strings.ReplaceAll(r.val, strings.ToUpper(old[6:]), strings.ToUpper(n[6:]))
			}
		}
	}
}

var (
	serialCols = [][]uint32{
		{1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1, 11},  // entPhysicalSerialNum
		{1, 0, 8802, 1, 1, 2, 1, 5, 1, 1, 2, 5}, // LLDP-MED inventory serial number (as some agents number it)
		{1, 0, 8802, 1, 1, 2, 1, 5, 4795, 1, 2, 5},
	}
	blanked = [][]uint32{{1, 3, 6, 1, 2, 1, 1, 4, 0}, {1, 3, 6, 1, 2, 1, 1, 6, 0}} // sysContact, sysLocation
)

// scrubSerials replaces every serial number found in the serial columns with zeros of the same
// length (keeping up to three leading capitals), wherever the value appears as text, and blanks
// sysContact and sysLocation.
func scrubSerials(recs []rec) {
	serials := map[string]string{}
	for _, r := range recs {
		for _, col := range serialCols {
			if r.tag == "4" && len(r.val) >= 4 && len(r.oid) > len(col) && !less(r.oid[:len(col)], col) && !less(col, r.oid[:len(col)]) {
				keep := 0 // a vendor's letter prefix (PSZ…) says nothing about the unit
				for keep < 3 && r.val[keep] >= 'A' && r.val[keep] <= 'Z' {
					keep++
				}
				serials[r.val] = r.val[:keep] + strings.Repeat("0", len(r.val)-keep)
			}
		}
	}
	for k := range recs {
		r := &recs[k]
		for _, b := range blanked {
			if !less(r.oid, b) && !less(b, r.oid) {
				r.tag, r.val = "4", ""
			}
		}
		if r.tag == "4" {
			for old, n := range serials {
				r.val = strings.ReplaceAll(r.val, old, n)
			}
		}
	}
}

// eui64 is the modified EUI-64 interface ID of a MAC (12 hex digits): U/L bit flipped, fffe inserted.
func eui64(h string) string {
	b, _ := hex.DecodeString(h[:2])
	return fmt.Sprintf("%02x", b[0]^2) + h[2:6] + "fffe" + h[6:]
}

// fdbMAC returns where the MAC starts in an FDB table OID, or -1.
func fdbMAC(oid []uint32) int {
	for _, p := range fdbPrefixes {
		if len(oid) >= len(p)+7 && !less(oid[:len(p)], p) && !less(p, oid[:len(p)]) {
			return len(oid) - 6
		}
	}
	return -1
}

func macHex(b []uint32) string {
	var s strings.Builder
	for _, x := range b {
		if x > 255 {
			return ""
		}
		fmt.Fprintf(&s, "%02x", x)
	}
	return s.String()
}

func parseOID(s string) ([]uint32, error) {
	parts := strings.Split(strings.TrimPrefix(s, "."), ".")
	oid := make([]uint32, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad OID %q", s)
		}
		oid[i] = uint32(v)
	}
	return oid, nil
}

func oidString(oid []uint32) string {
	parts := make([]string, len(oid))
	for i, x := range oid {
		parts[i] = strconv.FormatUint(uint64(x), 10)
	}
	return strings.Join(parts, ".")
}

func less(a, b []uint32) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "walk2snmprec:", err)
	os.Exit(1)
}
