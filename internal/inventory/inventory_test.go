package inventory

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `# Atlas lab
switch,10.0.0.2,core,2c,
arp,10.0.0.1,edge-rtr
router,10.0.0.9
10.0.0.3,closet-a,1,public,private

"10.0.0.4","quoted, alias",3,
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Device{
		{Role: "switch", Host: "10.0.0.2", Alias: "core", Version: "2c", Line: 2},
		{Role: "arp", Host: "10.0.0.1", Alias: "edge-rtr", Line: 3},
		{Role: "arp", Host: "10.0.0.9", Line: 4},
		{Role: "switch", Host: "10.0.0.3", Alias: "closet-a", Version: "1", Community: "public", Line: 5},
		{Role: "switch", Host: "10.0.0.4", Alias: "quoted, alias", Version: "3", Line: 7},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d devices: %+v", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseHeader(t *testing.T) {
	got, err := Parse(strings.NewReader("host,role,community\n10.0.0.2,switch,c1\n10.0.0.1,arp,\n10.0.0.5,,\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Community != "c1" || got[1].Role != "arp" || got[2].Role != "switch" {
		t.Errorf("header parse: %+v", got)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"host,role\n,switch\n", "host,role\n10.0.0.1,firewall\n"} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestParseBOMAndInlineComments(t *testing.T) {
	got, err := Parse(strings.NewReader("\ufeffrole,host,alias,version,community\nswitch,10.0.0.2,core # main core\nswitch,10.0.0.3,\"a # b\",2c,c#1\n"))
	if err != nil || len(got) != 2 || got[0].Alias != "core" || got[1].Alias != "a # b" || got[1].Community != "c#1" {
		t.Fatalf("%+v %v", got, err)
	}
}
