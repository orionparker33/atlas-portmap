package collect

import (
	"testing"
)

func TestLLDPCaps(t *testing.T) {
	// bridge(2)+router(4): 0x20|0x08 = 0x28; telephone(5)+bridge(2): 0x04|0x20 = 0x24.
	if c := LLDPCaps([]byte{0x28, 0x00}); !c.Bridge || !c.Router || c.Phone || c.AP {
		t.Errorf("0x28 = %+v", c)
	}
	if c := LLDPCaps([]byte{0x24}); !c.Phone || !c.Bridge {
		t.Errorf("0x24 = %+v", c)
	}
	if c := LLDPCaps([]byte{0x10}); !c.AP || c.Bridge {
		t.Errorf("0x10 = %+v", c)
	}
	if c := LLDPCaps([]byte{0x00, 0x80}); !c.Bridge { // LLDP-V2 cVLAN component (bit 8)
		t.Errorf("cVLAN = %+v", c)
	}
	if c := LLDPCaps(nil); c != (Caps{}) {
		t.Errorf("nil = %+v", c)
	}
	if s := LLDPCaps([]byte{0x28}).String(); s != "bridge,router" {
		t.Errorf("String = %q", s)
	}
}

func TestCDPCaps(t *testing.T) {
	if c := CDPCaps([]byte{0, 0, 0, 0x29}, "cisco WS-C3850-48P"); !c.Router || !c.Bridge || c.AP {
		t.Errorf("switch = %+v", c)
	}
	if c := CDPCaps([]byte{0, 0, 0x04, 0x90}, "Cisco IP Phone 8845"); !c.Phone || !c.Station {
		t.Errorf("phone = %+v", c)
	}
	if c := CDPCaps([]byte{0, 0, 0, 0x02}, "cisco AIR-AP2802I-B-K9"); !c.AP {
		t.Errorf("AIR AP = %+v", c)
	}
	if c := CDPCaps([]byte{0, 0, 0, 0x02}, "cisco C9120AXI-B"); !c.AP {
		t.Errorf("C9120 AP = %+v", c)
	}
	if c := CDPCaps([]byte{0, 0, 0, 0x08}, "cisco C9300-48P"); c.AP || !c.Bridge {
		t.Errorf("C9300 switch = %+v", c)
	}
}

func TestIfKey(t *testing.T) {
	for in, want := range map[string]string{
		"GigabitEthernet1/0/1": "gi1/0/1", "Gi1/0/1": "gi1/0/1", "TenGigabitEthernet1/1/1": "te1/1/1",
		"Ethernet1/49": "eth1/49", "Eth1/49": "eth1/49", "Port-channel10": "po10", "FastEthernet0/1": "fa0/1",
		"ge-0/0/1": "ge-0/0/1", " 1/1/1 ": "1/1/1",
	} {
		if got := IfKey(in); got != want {
			t.Errorf("IfKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func testSwitch() *Switch {
	sw := newSwitch("10.0.0.2")
	for _, f := range []*Interface{
		{IfIndex: 10101, Name: "Gi1/0/1", Descr: "GigabitEthernet1/0/1", Alias: "uplink", Type: 6},
		{IfIndex: 10102, Name: "Gi1/0/2", Descr: "GigabitEthernet1/0/2", Alias: "uplink", Type: 6},
		{IfIndex: 7, Name: "Vlan7", Descr: "Vlan7", Type: 53},
	} {
		sw.Interfaces[f.IfIndex] = f
	}
	sw.BridgePortIfIndex = map[int]int{1: 10101, 2: 10102}
	return sw
}

func TestResolveLLDPPort(t *testing.T) {
	sw := testSwitch()
	cases := []struct {
		name    string
		portNum int
		subtype int
		id      string
		desc    string
		want    int
		how     string
	}{
		{"ifName via interfaceName subtype", 99, 5, "Gi1/0/2", "", 10102, "lldpLocPortId"},
		{"long name abbreviates", 99, 5, "GigabitEthernet1/0/1", "", 10101, "lldpLocPortId"},
		{"desc when id is a MAC", 99, 3, "\x00\x11\x22\x33\x44\x55", "GigabitEthernet1/0/2", 10102, "lldpLocPortDesc"},
		{"local subtype numeric ifIndex", 99, 7, "10101", "", 10101, "lldpLocPortId(local)=ifIndex"},
		{"bridge port fallback", 2, 3, "\x00\x11\x22\x33\x44\x55", "", 10102, "lldpPortNumber=dot1dBasePort"},
		{"ifIndex fallback", 7, 3, "\x00\x11\x22\x33\x44\x55", "", 7, "lldpPortNumber=ifIndex"},
		{"ambiguous alias is not a match", 99, 1, "uplink", "", 0, "unresolved"},
		{"unresolved", 99, 3, "\x00\x11\x22\x33\x44\x55", "", 0, "unresolved"},
	}
	for _, c := range cases {
		got, how := ResolveLLDPPort(sw, c.portNum, c.subtype, []byte(c.id), c.desc)
		if got != c.want || how != c.how {
			t.Errorf("%s: got %d (%s), want %d (%s)", c.name, got, how, c.want, c.how)
		}
	}
}

func TestLLDPIDs(t *testing.T) {
	if got := lldpChassisID(4, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}); got != "00:11:22:33:44:55" {
		t.Errorf("chassis mac = %s", got)
	}
	if got := lldpChassisID(5, []byte{1, 10, 0, 0, 3}); got != "10.0.0.3" {
		t.Errorf("chassis net = %s", got)
	}
	if got := lldpPortID(3, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55}); got != "00:11:22:33:44:55" {
		t.Errorf("port mac = %s", got)
	}
	if got := lldpPortID(5, []byte("ge-0/0/24")); got != "ge-0/0/24" {
		t.Errorf("port name = %s", got)
	}
}

func TestInterfaceHelpers(t *testing.T) {
	f := &Interface{IfIndex: 3, Type: 117, Admin: 1, Oper: 1}
	if f.Label() != "ifIndex 3" || !f.Physical() || f.Status() != "up" {
		t.Errorf("helpers: %q %v %q", f.Label(), f.Physical(), f.Status())
	}
	for in, want := range map[[2]int]string{{2, 2}: "disabled", {1, 2}: "down", {1, 7}: "down", {1, 5}: "dormant", {1, 0}: ""} {
		f := &Interface{Admin: in[0], Oper: in[1]}
		if got := f.Status(); got != want {
			t.Errorf("Status(%v) = %q, want %q", in, got, want)
		}
	}
	if (&Interface{Type: 53}).Physical() || (&Interface{Type: 161}).Physical() {
		t.Error("virtual/LAG counted as physical")
	}
}
