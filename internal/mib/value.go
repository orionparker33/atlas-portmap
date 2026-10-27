package mib

import (
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/macaddr"
)

// Missing reports SNMP exceptions (noSuchObject, noSuchInstance, endOfMibView) and nulls.
func Missing(p gosnmp.SnmpPDU) bool {
	switch p.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return true
	}
	return p.Value == nil
}

// IntValue returns the value of any integer-typed PDU (Integer, Counter32/64, Gauge32,
// TimeTicks, Uinteger32).
func IntValue(p gosnmp.SnmpPDU) (int64, bool) {
	switch p.Type {
	case gosnmp.Integer, gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Counter64, gosnmp.Uinteger32:
	default:
		return 0, false
	}
	switch v := p.Value.(type) {
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		if uint64(v) > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	case uint8:
		return int64(v), true
	case uint16:
		return int64(v), true
	case uint32:
		return int64(v), true
	case uint64:
		if v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	}
	return 0, false
}

// Bytes returns an OCTET STRING (or BITS) value.
func Bytes(p gosnmp.SnmpPDU) ([]byte, bool) {
	if p.Type != gosnmp.OctetString {
		return nil, false
	}
	b, ok := p.Value.([]byte)
	return b, ok
}

// PortList decodes a Q-BRIDGE PortList bitmap into port numbers: the first octet's most
// significant bit is port 1. Any length is accepted.
func PortList(b []byte) []int {
	var out []int
	for i, x := range b {
		for bit := 0; bit < 8; bit++ {
			if x&(0x80>>bit) != 0 {
				out = append(out, i*8+bit+1)
			}
		}
	}
	return out
}

// Text renders a value for display: printable OCTET STRINGs as text, other OCTET STRINGs as
// hex, numbers in decimal, OIDs and IP addresses as-is.
func Text(p gosnmp.SnmpPDU) string {
	switch p.Type {
	case gosnmp.OctetString:
		b, _ := p.Value.([]byte)
		return OctetText(b)
	case gosnmp.ObjectIdentifier:
		s, _ := p.Value.(string)
		return Norm(s)
	case gosnmp.IPAddress:
		s, _ := p.Value.(string)
		return s
	}
	if n, ok := IntValue(p); ok {
		return strconv.FormatInt(n, 10)
	}
	if Missing(p) {
		return ""
	}
	return fmt.Sprint(p.Value)
}

// OctetText renders an OCTET STRING as trimmed text when it is printable UTF-8, else as
// colon-separated hex. Control characters (C0, DEL, C1) make a value non-printable, so
// strings from a device cannot inject terminal escape sequences.
func OctetText(b []byte) string {
	t := strings.TrimRight(string(b), "\x00")
	if utf8.ValidString(t) && printable(t) {
		return strings.TrimSpace(t)
	}
	return hexColon(b)
}

func printable(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}

func hexColon(b []byte) string {
	h := hex.EncodeToString(b)
	var s strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			s.WriteByte(':')
		}
		s.WriteString(h[i : i+2])
	}
	return s.String()
}

// MACValue decodes a PhysAddress / MacAddress value. Agents normally send 6 raw octets; a few
// send text ("00:11:22:33:44:55", "0011.2233.4455", …).
func MACValue(p gosnmp.SnmpPDU) (net.HardwareAddr, bool) {
	b, ok := Bytes(p)
	if !ok {
		return nil, false
	}
	if len(b) == 6 {
		return net.HardwareAddr(append([]byte(nil), b...)), true
	}
	if m, err := macaddr.Parse(string(b)); err == nil {
		return m, true
	}
	return nil, false
}

// TypeName names a PDU's ASN.1 type the way net-snmp prints it.
func TypeName(t gosnmp.Asn1BER) string {
	switch t {
	case gosnmp.Integer:
		return "INTEGER"
	case gosnmp.OctetString:
		return "STRING"
	case gosnmp.ObjectIdentifier:
		return "OID"
	case gosnmp.IPAddress:
		return "IpAddress"
	case gosnmp.Counter32:
		return "Counter32"
	case gosnmp.Gauge32:
		return "Gauge32"
	case gosnmp.TimeTicks:
		return "Timeticks"
	case gosnmp.Counter64:
		return "Counter64"
	case gosnmp.Uinteger32:
		return "UInteger32"
	case gosnmp.Null:
		return "NULL"
	case gosnmp.NoSuchObject:
		return "noSuchObject"
	case gosnmp.NoSuchInstance:
		return "noSuchInstance"
	case gosnmp.EndOfMibView:
		return "endOfMibView"
	}
	return fmt.Sprintf("type-0x%02x", byte(t))
}
