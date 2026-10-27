package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/orionparker33/atlas-portmap/internal/portmap"
)

func report() *Report {
	return &Report{Tool: "atlas-portmap", Version: "test", Entries: []portmap.Entry{
		{Switch: "core", SwitchAddr: "10.0.0.2", Port: "Gi1/0/1", PortAlias: "desk\x1b[2J 12", VLAN: 10, MAC: "00:50:56:00:00:0a",
			Vendor: "VMware, Inc.", IPs: []string{"10.0.10.5"}, PortStatus: "up", MACsOnPort: 1, Extra: map[string]string{"poe": "on"}},
		{Switch: "core", Port: "Gi1/0/2", PortAlias: "=HYPERLINK(\"http://x\")", MACsOnPort: 4, Uplink: true, UplinkReason: "faces access"},
	}}
}

func TestTable(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "table", report()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "\x1b") {
		t.Error("escape sequence reached the terminal table")
	}
	for _, want := range []string{"SWITCH", "ALIAS", "POE", "NOTE", "Gi1/0/1", "10.0.10.5", "4 MACs, placed elsewhere; uplink: faces access"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "HOSTNAME") || strings.Contains(out, "802.1X") {
		t.Errorf("empty optional columns shown:\n%s", out)
	}
}

func TestCSV(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "csv", report()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&b).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0][len(rows[0])-1] != "poe" {
		t.Fatalf("csv shape: %v", rows)
	}
	if alias := rows[2][3]; !strings.HasPrefix(alias, "'=") {
		t.Errorf("formula not neutralised: %q", alias)
	}
	// An imported report can put a formula in any field, MAC and IP included.
	var b2 bytes.Buffer
	evil := &Report{Entries: []portmap.Entry{{Switch: "s", Port: "p", MAC: "=1+1", IPs: []string{"@SUM(A1)"}, PortStatus: "+x"}}}
	if err := Write(&b2, "csv", evil); err != nil {
		t.Fatal(err)
	}
	r2, _ := csv.NewReader(&b2).ReadAll()
	for _, cell := range r2[1] {
		if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
			t.Errorf("unescaped cell %q", cell)
		}
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "json", report()); err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(b.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 2 || r.Entries[0].Extra["poe"] != "on" || r.Entries[0].PortAlias != "desk\x1b[2J 12" {
		t.Errorf("round trip: %+v", r.Entries)
	}
	if err := Write(&b, "yaml", report()); err == nil {
		t.Error("unknown format accepted")
	}
}
