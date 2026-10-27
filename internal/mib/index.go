package mib

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Norm strips a leading dot so agent OIDs (".1.3.6…") compare with the constants.
func Norm(oid string) string { return strings.TrimPrefix(strings.TrimSpace(oid), ".") }

// Suffix returns the row index of oid beneath column ("1.3.6.1.2.1.2.2.1.2" and
// ".1.3.6.1.2.1.2.2.1.2.7" give "7"). ok is false unless oid is strictly under column.
func Suffix(oid, column string) (string, bool) {
	o, c := Norm(oid), Norm(column)
	if !strings.HasPrefix(o, c+".") {
		return "", false
	}
	return o[len(c)+1:], true
}

// Ints parses a dotted index into its sub-identifiers.
func Ints(index string) ([]uint32, error) {
	if index == "" {
		return nil, errors.New("empty index")
	}
	parts := strings.Split(index, ".")
	out := make([]uint32, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bad sub-identifier %q in index %q", p, index)
		}
		out[i] = uint32(v)
	}
	return out, nil
}

// Int parses a single-component index (ifIndex, bridge port, VLAN ID).
func Int(index string) (int, error) {
	v, err := Ints(index)
	if err != nil {
		return 0, err
	}
	if len(v) != 1 {
		return 0, fmt.Errorf("index %q has %d components, want 1", index, len(v))
	}
	return int(v[0]), nil
}

func octets(v []uint32) ([]byte, error) {
	b := make([]byte, len(v))
	for i, x := range v {
		if x > 255 {
			return nil, fmt.Errorf("sub-identifier %d is not an octet", x)
		}
		b[i] = byte(x)
	}
	return b, nil
}

// MAC decodes a 6-component MAC index (dot1dTpFdbAddress, dot1qTpFdbAddress).
func MAC(v []uint32) (net.HardwareAddr, error) {
	if len(v) != 6 {
		return nil, fmt.Errorf("MAC index has %d components, want 6", len(v))
	}
	b, err := octets(v)
	if err != nil {
		return nil, err
	}
	return net.HardwareAddr(b), nil
}

// NetToMediaIndex decodes ipNetToMediaTable's index: ifIndex.a.b.c.d.
func NetToMediaIndex(v []uint32) (int, net.IP, error) {
	if len(v) != 5 {
		return 0, nil, fmt.Errorf("ipNetToMedia index has %d components, want 5", len(v))
	}
	b, err := octets(v[1:])
	if err != nil {
		return 0, nil, err
	}
	return int(v[0]), net.IPv4(b[0], b[1], b[2], b[3]), nil
}

// NetToPhysicalIndex decodes ipNetToPhysicalTable's index: ifIndex.addrType.len.addr…
// InetAddress is not IMPLIED, so the address carries a length prefix (RFC 4293). Agents that
// omit the prefix are accepted too: the lengths cannot collide. Only ipv4(1) and ipv6(2) are
// decoded; zoned types are rejected.
func NetToPhysicalIndex(v []uint32) (int, net.IP, error) {
	if len(v) < 3 {
		return 0, nil, fmt.Errorf("ipNetToPhysical index too short (%d components)", len(v))
	}
	ifIndex, typ := int(v[0]), v[1]
	var addr []uint32
	switch {
	case typ == 1 && len(v) == 7 && v[2] == 4, typ == 2 && len(v) == 19 && v[2] == 16:
		addr = v[3:]
	case typ == 1 && len(v) == 6, typ == 2 && len(v) == 18:
		addr = v[2:]
	default:
		return 0, nil, fmt.Errorf("unsupported ipNetToPhysical index (type %d, %d components)", typ, len(v))
	}
	b, err := octets(addr)
	if err != nil {
		return 0, nil, err
	}
	if typ == 1 {
		return ifIndex, net.IPv4(b[0], b[1], b[2], b[3]), nil
	}
	return ifIndex, net.IP(b), nil
}

// Enterprise returns the IANA Private Enterprise Number in a sysObjectID
// (1.3.6.1.4.1.<n>.…), or -1 when oid is not under enterprises.
func Enterprise(oid string) int {
	const prefix = "1.3.6.1.4.1."
	o := Norm(oid)
	if !strings.HasPrefix(o, prefix) {
		return -1
	}
	rest := o[len(prefix):]
	if i := strings.IndexByte(rest, '.'); i >= 0 {
		rest = rest[:i]
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// ValidOID reports whether s is a numeric OID with at least two components.
func ValidOID(s string) bool {
	v, err := Ints(Norm(s))
	return err == nil && len(v) >= 2
}
