package mib

import (
	"net"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestSuffix(t *testing.T) {
	cases := []struct {
		oid, col, want string
		ok             bool
	}{
		{".1.3.6.1.2.1.2.2.1.2.7", IfDescr, "7", true},
		{"1.3.6.1.2.1.2.2.1.2.7", "." + IfDescr, "7", true},
		{"1.3.6.1.2.1.17.4.3.1.2.0.27.99.10.11.12", Dot1dTpFdbPort, "0.27.99.10.11.12", true},
		{"1.3.6.1.2.1.2.2.1.20.5", IfDescr, "", false}, // sibling column with a shared prefix
		{"1.3.6.1.2.1.2.2.1.2", IfDescr, "", false},    // the column itself
	}
	for _, c := range cases {
		got, ok := Suffix(c.oid, c.col)
		if got != c.want || ok != c.ok {
			t.Errorf("Suffix(%s, %s) = %q, %v; want %q, %v", c.oid, c.col, got, ok, c.want, c.ok)
		}
	}
}

func TestIndexDecoders(t *testing.T) {
	if _, err := Ints("1.x.3"); err == nil {
		t.Error("Ints accepted a non-number")
	}
	if _, err := Int("1.2"); err == nil {
		t.Error("Int accepted two components")
	}
	m, err := MAC([]uint32{0, 27, 99, 10, 11, 12})
	if err != nil || m.String() != "00:1b:63:0a:0b:0c" {
		t.Errorf("MAC = %v, %v", m, err)
	}
	if _, err := MAC([]uint32{0, 27, 99, 10, 11, 300}); err == nil {
		t.Error("MAC accepted 300")
	}
	ifx, ip, err := NetToMediaIndex([]uint32{5, 10, 0, 0, 1})
	if err != nil || ifx != 5 || !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("NetToMediaIndex = %d %v %v", ifx, ip, err)
	}
	for _, c := range []struct {
		in   []uint32
		ifx  int
		want string
	}{
		{[]uint32{7, 1, 4, 192, 168, 1, 9}, 7, "192.168.1.9"},
		{[]uint32{7, 1, 192, 168, 1, 9}, 7, "192.168.1.9"}, // no length prefix
		{[]uint32{7, 1, 4, 1, 2, 3}, 7, "4.1.2.3"},         // 6 components can only be the unprefixed form
		{append([]uint32{8, 2, 16}, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 8, "fe80::1"},
	} {
		ifx, ip, err := NetToPhysicalIndex(c.in)
		if err != nil || ifx != c.ifx || ip.String() != c.want {
			t.Errorf("NetToPhysicalIndex(%v) = %d %v %v; want %d %s", c.in, ifx, ip, err, c.ifx, c.want)
		}
	}
	for _, bad := range [][]uint32{{7, 3, 4, 1, 2, 3, 4}, {7, 1, 4, 1, 2, 3, 4, 5}, {7}, {7, 1, 4, 1, 2, 3, 999}, {7, 2, 16, 1, 2}} {
		if _, _, err := NetToPhysicalIndex(bad); err == nil {
			t.Errorf("NetToPhysicalIndex(%v) accepted", bad)
		}
	}
}

func TestEnterpriseAndValidOID(t *testing.T) {
	for in, want := range map[string]int{
		"1.3.6.1.4.1.9.1.1208": 9, ".1.3.6.1.4.1.2636.1.1.1.2.29": 2636, "1.3.6.1.4.1.11": 11,
		"1.3.6.1.2.1.1": -1, "1.3.6.1.4.1.": -1, "": -1,
	} {
		if got := Enterprise(in); got != want {
			t.Errorf("Enterprise(%q) = %d, want %d", in, got, want)
		}
	}
	if !ValidOID("1.3.6.1.2.1.31.1.1.1.18") || !ValidOID(".1.3") || ValidOID("1") || ValidOID("ifAlias") || ValidOID("1.3.x") {
		t.Error("ValidOID wrong")
	}
}

func TestValues(t *testing.T) {
	for _, p := range []gosnmp.SnmpPDU{
		{Type: gosnmp.Integer, Value: 42}, {Type: gosnmp.Gauge32, Value: uint(42)},
		{Type: gosnmp.Counter32, Value: uint(42)}, {Type: gosnmp.TimeTicks, Value: uint32(42)},
		{Type: gosnmp.Counter64, Value: uint64(42)},
	} {
		if v, ok := IntValue(p); !ok || v != 42 {
			t.Errorf("IntValue(%v) = %d, %v", p, v, ok)
		}
	}
	if _, ok := IntValue(gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("42")}); ok {
		t.Error("IntValue accepted a string")
	}
	if !Missing(gosnmp.SnmpPDU{Type: gosnmp.NoSuchInstance}) || Missing(gosnmp.SnmpPDU{Type: gosnmp.Integer, Value: 0}) {
		t.Error("Missing wrong")
	}
	for in, want := range map[string]string{
		"Gi1/0/1":         "Gi1/0/1",
		"desk 12\x00\x00": "desk 12",
		"\x1b[2Jpwned":    "1b:5b:32:4a:70:77:6e:65:64", // ESC: rendered as hex, never emitted raw
		"\u009bevil":      "c2:9b:65:76:69:6c",          // C1 CSI
		"\x00\x1b\x63":    "00:1b:63",
	} {
		if got := OctetText([]byte(in)); got != want {
			t.Errorf("OctetText(%q) = %q, want %q", in, got, want)
		}
	}
	raw := gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte{0, 0x1b, 0x63, 0x0a, 0x0b, 0x0c}}
	txt := gosnmp.SnmpPDU{Type: gosnmp.OctetString, Value: []byte("00:1b:63:0a:0b:0c")}
	for _, p := range []gosnmp.SnmpPDU{raw, txt} {
		if m, ok := MACValue(p); !ok || m.String() != "00:1b:63:0a:0b:0c" {
			t.Errorf("MACValue(%v) = %v, %v", p.Value, m, ok)
		}
	}
	if Text(gosnmp.SnmpPDU{Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.9"}) != "1.3.6.1.4.1.9" {
		t.Error("Text(OID) kept the leading dot")
	}
}
