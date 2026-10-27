package macaddr

import (
	"net"
	"testing"
)

func TestParse(t *testing.T) {
	want := "00:1b:63:0a:0b:0c"
	for _, in := range []string{
		"00:1b:63:0a:0b:0c", "00-1B-63-0A-0B-0C", "001b.630a.0b0c", "001b630a0b0c",
		"00 1b 63 0a 0b 0c", "0:1b:63:a:b:c", "  00:1b:63:0a:0b:0c\n",
	} {
		m, err := Parse(in)
		if err != nil || m.String() != want {
			t.Errorf("Parse(%q) = %v, %v; want %s", in, m, err, want)
		}
	}
	for _, in := range []string{
		"", "00:1b:63:0a:0b", "00:1b:63:0a:0b:0c:0d", "001b:630a:0b0c:00", "zz:1b:63:0a:0b:0c",
		"001:b6:30:a0:b0:c0", "1.3.6.1.4.1.9.1.1208", "00.1b.63.0a.0b.0c", "001b630a0b0", "001b.630a.0b0", "1.2.3",
	} {
		if m, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want error", in, m)
		}
	}
}

func TestFormat(t *testing.T) {
	m := net.HardwareAddr{0x00, 0x1b, 0x63, 0x0a, 0x0b, 0x0c}
	for style, want := range map[string]string{
		"colon": "00:1b:63:0a:0b:0c", "": "00:1b:63:0a:0b:0c", "dash": "00-1B-63-0A-0B-0C",
		"dot": "001b.630a.0b0c", "bare": "001b630a0b0c",
	} {
		if got := Format(m, style); got != want {
			t.Errorf("Format(%q) = %s, want %s", style, got, want)
		}
	}
}

func TestUsableAndLocal(t *testing.T) {
	for in, want := range map[string]bool{
		"00:1b:63:0a:0b:0c": true, "02:42:ac:11:00:02": true, "00:00:00:00:00:00": false,
		"ff:ff:ff:ff:ff:ff": false, "01:00:5e:00:00:01": false, "33:33:00:00:00:01": false,
	} {
		m, _ := Parse(in)
		if got := Usable(m); got != want {
			t.Errorf("Usable(%s) = %v, want %v", in, got, want)
		}
	}
	if Usable(net.HardwareAddr{1, 2, 3}) {
		t.Error("3-octet address usable")
	}
	l, _ := Parse("02:42:ac:11:00:02")
	g, _ := Parse("00:1b:63:0a:0b:0c")
	if !LocallyAdministered(l) || LocallyAdministered(g) {
		t.Error("LocallyAdministered wrong")
	}
}
