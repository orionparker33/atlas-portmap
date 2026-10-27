package vendordb

import (
	"net"
	"strings"
	"testing"
)

func TestEmbeddedData(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if o, p := db.Counts(); o < 50000 || p < 60000 {
		t.Fatalf("embedded data too small: %d prefixes, %d enterprises", o, p)
	}
	for in, want := range map[string]string{
		"00:00:0c:12:34:56": "Cisco",        // MA-L
		"00:50:56:01:02:03": "VMware",       // MA-L
		"b8:27:eb:01:02:03": "Raspberry Pi", // MA-L
		"02:42:ac:11:00:02": Locally,        // U/L bit
	} {
		m, _ := net.ParseMAC(in)
		if got := db.MAC(m); !strings.Contains(got, want) {
			t.Errorf("MAC(%s) = %q, want %q", in, got, want)
		}
	}
	// 70:B3:D5 is IEEE's MA-S/IAB block: the 36-bit assignment must win over any 24-bit one.
	m, _ := net.ParseMAC("70:b3:d5:01:20:00")
	if got := db.MAC(m); got == "" || got == "IEEE Registration Authority" {
		t.Errorf("MA-S longest-prefix lookup = %q", got)
	}
	if n, org := db.Enterprise("1.3.6.1.4.1.9.1.1208"); n != 9 || org == "" {
		t.Errorf("Enterprise(cisco) = %d %q", n, org)
	}
	if n, _ := db.Enterprise("1.3.6.1.2.1.1"); n != -1 {
		t.Errorf("Enterprise(non-enterprise) = %d", n)
	}
	if db.MAC(net.HardwareAddr{1}) != "" {
		t.Error("short MAC")
	}
}
