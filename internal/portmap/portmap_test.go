package portmap

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/collect"
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

const (
	mA    = "00:50:56:00:00:0a" // server on core Gi1/0/1
	mB    = "b8:27:eb:00:00:0b" // device on access ge-0/0/1
	mC    = "00:00:0c:00:00:0c" // phone on access ge-0/0/2
	mD    = "00:15:5d:00:00:0d" // PC behind the phone
	mE    = "00:00:0c:00:00:0e" // learned on an unmapped bridge port
	mCore = "00:00:0c:cc:cc:cc" // core's base MAC
	mAcc  = "00:00:0c:aa:aa:aa" // access's base MAC
	mVM1  = "02:00:00:00:00:01" // locally administered VMs on core Gi1/0/4
	mVM2  = "02:00:00:00:00:02"
)

func iface(idx int, name string, oper int) *collect.Interface {
	return &collect.Interface{IfIndex: idx, Name: name, Type: 6, Admin: 1, Oper: oper}
}

// topology: core (Q-BRIDGE, VLAN-tagged FDB) cascades to access (BRIDGE-MIB, VLAN from PVID).
func topology() ([]*collect.Switch, []collect.ARPEntry) {
	core := &collect.Switch{
		Target: "10.0.0.2", SysName: "core", BaseMAC: mac(mCore),
		Interfaces: map[int]*collect.Interface{
			1: iface(1, "Gi1/0/1", 1), 2: iface(2, "Gi1/0/2", 1), 3: iface(3, "Gi1/0/3", 2), 4: iface(4, "Gi1/0/4", 1),
			100: {IfIndex: 100, Name: "Vlan10", Type: 53, Oper: 1},
		},
		BridgePortIfIndex: map[int]int{1: 1, 2: 2, 3: 3, 4: 4},
		PVID:              map[int]int{1: 10, 2: 1, 4: 30},
		VLANNames:         map[int]string{10: "users", 20: "voice"},
		FDB: []collect.FDBEntry{
			{MAC: mac(mA), BridgePort: 1, VLAN: 10, Status: collect.FDBLearned},
			{MAC: mac(mB), BridgePort: 2, VLAN: 20, Status: collect.FDBLearned},
			{MAC: mac(mC), BridgePort: 2, VLAN: 20, Status: collect.FDBLearned},
			{MAC: mac(mD), BridgePort: 2, VLAN: 20, Status: collect.FDBLearned},
			{MAC: mac(mAcc), BridgePort: 2, VLAN: 1, Status: collect.FDBLearned},
			{MAC: mac(mCore), BridgePort: 1, VLAN: 1, Status: collect.FDBSelf},                  // own MAC: dropped
			{MAC: mac("00:00:0c:00:00:99"), BridgePort: 3, VLAN: 1, Status: collect.FDBInvalid}, // dropped
			{MAC: mac("01:00:5e:00:00:01"), BridgePort: 1, VLAN: 10, Status: collect.FDBMgmt},   // multicast: dropped
			{MAC: mac(mVM1), BridgePort: 4, VLAN: 30, Status: collect.FDBLearned},
			{MAC: mac(mVM2), BridgePort: 4, VLAN: 30, Status: collect.FDBLearned},
		},
		Neighbors: []collect.Neighbor{
			{IfIndex: 2, Protocol: "lldp", SysName: "access.lab.example", PortID: "ge-0/0/24", Caps: collect.Caps{Bridge: true}},
		},
	}
	access := &collect.Switch{
		Target: "10.0.0.3", SysName: "access", BaseMAC: mac(mAcc),
		Interfaces: map[int]*collect.Interface{
			101: iface(101, "ge-0/0/1", 1), 102: iface(102, "ge-0/0/2", 1), 124: iface(124, "ge-0/0/24", 1), 125: iface(125, "ge-0/0/25", 2),
		},
		BridgePortIfIndex: map[int]int{1: 101, 2: 102, 24: 124, 25: 125},
		PVID:              map[int]int{1: 20, 2: 20, 24: 1},
		FDB: []collect.FDBEntry{
			{MAC: mac(mB), BridgePort: 1},
			{MAC: mac(mC), BridgePort: 2},
			{MAC: mac(mD), BridgePort: 2},
			{MAC: mac(mA), BridgePort: 24},
			{MAC: mac(mCore), BridgePort: 24},
			{MAC: mac(mE), BridgePort: 99}, // no ifIndex mapping
		},
		Neighbors: []collect.Neighbor{
			{IfIndex: 102, Protocol: "lldp", SysName: "SEP0000C000000C", Caps: collect.Caps{Phone: true, Bridge: true}},
		},
	}
	arp := []collect.ARPEntry{
		{IP: net.ParseIP("10.0.10.5"), MAC: mac(mA)},
		{IP: net.ParseIP("fe80::1"), MAC: mac(mB)},
		{IP: net.ParseIP("10.0.20.6"), MAC: mac(mB)},
		{IP: net.ParseIP("10.0.20.6"), MAC: mac(mB)}, // duplicate from a second source
		{IP: net.ParseIP("10.0.20.8"), MAC: mac(mD)},
	}
	return []*collect.Switch{core, access}, arp
}

func byMAC(entries []Entry) map[string][]Entry {
	out := map[string][]Entry{}
	for _, e := range entries {
		out[e.MAC] = append(out[e.MAC], e)
	}
	return out
}

func TestBuildPlacesEachMACAtItsEdgePort(t *testing.T) {
	sw, arp := topology()
	got := byMAC(Build(sw, arp, Options{UplinkThreshold: 10, Vendor: func(net.HardwareAddr) string { return "V" }}))

	want := map[string]struct {
		sw, port string
		vlan     int
		ips      string
	}{
		mA:    {"core", "Gi1/0/1", 10, "10.0.10.5"},            // not access ge-0/0/24 (faces core)
		mB:    {"access", "ge-0/0/1", 20, "10.0.20.6,fe80::1"}, // not core Gi1/0/2 (faces access); VLAN via PVID
		mC:    {"access", "ge-0/0/2", 20, ""},
		mD:    {"access", "ge-0/0/2", 20, "10.0.20.8"},
		mAcc:  {"core", "Gi1/0/2", 1, ""},     // only sighting: the access switch itself, via the uplink
		mCore: {"access", "ge-0/0/24", 1, ""}, // own entry on core is "self" and dropped
		mVM1:  {"core", "Gi1/0/4", 30, ""},
		mVM2:  {"core", "Gi1/0/4", 30, ""},
		mE:    {"access", "bridge port 99", 0, ""},
	}
	if len(got) != len(want) {
		t.Errorf("got %d MACs, want %d: %v", len(got), len(want), keys(got))
	}
	for m, w := range want {
		rows := got[m]
		if len(rows) != 1 {
			t.Errorf("%s: %d rows", m, len(rows))
			continue
		}
		e := rows[0]
		if e.Switch != w.sw || e.Port != w.port || e.VLAN != w.vlan || strings.Join(e.IPs, ",") != w.ips || e.Vendor != "V" || e.Secondary {
			t.Errorf("%s: got %s %s vlan %d ips %v vendor %q secondary %v; want %+v", m, e.Switch, e.Port, e.VLAN, e.IPs, e.Vendor, e.Secondary, w)
		}
	}
	for _, m := range []string{"00:00:0c:00:00:99", "01:00:5e:00:00:01"} {
		if _, ok := got[m]; ok {
			t.Errorf("%s should have been filtered", m)
		}
	}
	a := got[mA][0]
	if a.VLANName != "users" || a.IfIndex != 1 || a.BridgePort != 1 || a.Uplink || a.PortStatus != "up" {
		t.Errorf("A row: %+v", a)
	}
	if b := got[mB][0]; len(b.AlsoSeen) != 1 || b.AlsoSeen[0] != "core Gi1/0/2" || b.MACsOnPort != 1 {
		t.Errorf("B also_seen/macs: %+v", b)
	}
	if c := got[mC][0]; c.Uplink || !strings.Contains(c.Neighbor, "SEP0000C000000C") || c.MACsOnPort != 2 {
		t.Errorf("phone port must not be an uplink: %+v", c)
	}
	if u := got[mAcc][0]; !u.Uplink || u.UplinkKind != "switch" || u.UplinkReason != "faces access" || !strings.Contains(u.Neighbor, "lldp access.lab.example port ge-0/0/24") {
		t.Errorf("core uplink: %+v", u)
	}
	if u := got[mCore][0]; !u.Uplink || u.UplinkReason != "faces core" {
		t.Errorf("access uplink (by base MAC): %+v", u)
	}
	if e := got[mE][0]; e.IfIndex != 0 || e.BridgePort != 99 {
		t.Errorf("unresolved bridge port: %+v", e)
	}
}

func TestBuildManagementIPMarksUplink(t *testing.T) {
	sw, arp := topology()
	core, access := sw[0], sw[1]
	core.Neighbors, access.Neighbors = nil, nil // no LLDP at all
	core.BaseMAC, access.BaseMAC = nil, nil     // and no bridge base MAC
	access.FDB = append(access.FDB, collect.FDBEntry{MAC: mac("00:00:0c:dd:dd:dd"), BridgePort: 24})
	arp = append(arp, collect.ARPEntry{IP: net.ParseIP("10.0.0.2"), MAC: mac("00:00:0c:dd:dd:dd")}) // core's mgmt IP
	got := byMAC(Build(sw, arp, Options{}))
	if a := got[mA][0]; a.Switch != "core" || a.Port != "Gi1/0/1" {
		t.Errorf("A placed at %s %s", a.Switch, a.Port)
	}
	if u := got["00:00:0c:dd:dd:dd"][0]; u.UplinkReason != "faces core" {
		t.Errorf("mgmt-IP uplink: %+v", u)
	}
	// Without LLDP, B is still placed on the access port: fewest MACs wins.
	if b := got[mB][0]; b.Switch != "access" || b.Port != "ge-0/0/1" {
		t.Errorf("B placed at %s %s", b.Switch, b.Port)
	}
}

func TestBuildAllSightings(t *testing.T) {
	sw, arp := topology()
	rows := byMAC(Build(sw, arp, Options{AllSightings: true}))[mB]
	if len(rows) != 2 {
		t.Fatalf("B rows = %d", len(rows))
	}
	var primary, secondary int
	for _, r := range rows {
		if r.Secondary {
			secondary++
			if r.Switch != "core" || r.VLAN != 20 {
				t.Errorf("secondary row %+v", r)
			}
		} else {
			primary++
		}
	}
	if primary != 1 || secondary != 1 {
		t.Errorf("primary %d secondary %d", primary, secondary)
	}
}

func TestBuildAllPorts(t *testing.T) {
	sw, arp := topology()
	var empty []string
	for _, e := range Build(sw, arp, Options{AllPorts: true}) {
		if e.MAC == "" {
			empty = append(empty, e.Switch+" "+e.Port)
		}
	}
	want := "access ge-0/0/25,core Gi1/0/3"
	if got := strings.Join(sorted(empty), ","); got != want {
		t.Errorf("empty ports = %s, want %s (Vlan10 is virtual and excluded)", got, want)
	}
}

func TestHeuristicUplinks(t *testing.T) {
	// A bridge/router neighbour (a hypervisor running lldpd) marks its port.
	sw, arp := topology()
	sw[0].Neighbors = append(sw[0].Neighbors, collect.Neighbor{IfIndex: 4, Protocol: "lldp", SysName: "hv1", Caps: collect.Caps{Bridge: true, Router: true}})
	got := byMAC(Build(sw, arp, Options{UplinkThreshold: 10}))
	if v := got[mVM1][0]; !v.Uplink || v.UplinkKind != "bridge" || v.UplinkReason != "lldp neighbour hv1 is a bridge/router" {
		t.Errorf("bridge neighbour: %+v", v)
	}
	// The MAC-count threshold marks a port with no neighbour, but never a phone's port.
	sw, arp = topology()
	got = byMAC(Build(sw, arp, Options{UplinkThreshold: 2}))
	if v := got[mVM1][0]; !v.Uplink || v.UplinkKind != "many-macs" || v.UplinkReason != "2 MACs learned" {
		t.Errorf("threshold: %+v", v)
	}
	if c := got[mC][0]; c.Uplink {
		t.Errorf("phone port marked as uplink by the threshold: %+v", c)
	}
}

func TestAccessPointPortIsNotAnUplink(t *testing.T) {
	s := &collect.Switch{Target: "10.0.0.3", SysName: "access",
		Interfaces:        map[int]*collect.Interface{3: iface(3, "1/3", 1)},
		BridgePortIfIndex: map[int]int{3: 3},
		Neighbors:         []collect.Neighbor{{IfIndex: 3, Protocol: "lldp", SysName: "ap-lobby", Caps: collect.Caps{AP: true, Bridge: true}}},
	}
	for i := 0; i < 15; i++ {
		s.FDB = append(s.FDB, collect.FDBEntry{MAC: net.HardwareAddr{0xda, 0xa1, 0x19, 0, 0, byte(i)}, BridgePort: 3, VLAN: 10})
	}
	for _, e := range Build([]*collect.Switch{s}, nil, Options{UplinkThreshold: 10}) {
		if e.Uplink {
			t.Fatalf("AP port flagged as uplink: %+v", e)
		}
	}
}

// A hypervisor's VMs are learned on its port and on an upstream port that faces a mapped
// switch. Even when the upstream port has learned fewer MACs (aging), the VMs stay on the
// hypervisor port: a provable uplink is never the answer when another sighting exists.
func TestDefinitiveUplinkLosesEvenWithFewerMACs(t *testing.T) {
	core := &collect.Switch{Target: "10.0.0.2", SysName: "core",
		Interfaces:        map[int]*collect.Interface{1: iface(1, "Gi1/0/1", 1)},
		BridgePortIfIndex: map[int]int{1: 1},
		FDB:               []collect.FDBEntry{{MAC: mac(mVM1), BridgePort: 1, VLAN: 30}},
		Neighbors:         []collect.Neighbor{{IfIndex: 1, Protocol: "lldp", SysName: "access", Caps: collect.Caps{Bridge: true}}},
	}
	access := &collect.Switch{Target: "10.0.0.3", SysName: "access",
		Interfaces:        map[int]*collect.Interface{5: iface(5, "ge-0/0/5", 1)},
		BridgePortIfIndex: map[int]int{5: 5},
		Neighbors:         []collect.Neighbor{{IfIndex: 5, Protocol: "lldp", SysName: "hv1", Caps: collect.Caps{Bridge: true, Router: true}}},
	}
	for i := 0; i < 20; i++ {
		access.FDB = append(access.FDB, collect.FDBEntry{MAC: net.HardwareAddr{2, 0, 0, 0, 1, byte(i)}, BridgePort: 5, VLAN: 30})
	}
	access.FDB = append(access.FDB, collect.FDBEntry{MAC: mac(mVM1), BridgePort: 5, VLAN: 30})
	got := byMAC(Build([]*collect.Switch{core, access}, nil, Options{UplinkThreshold: 10}))
	if v := got[mVM1][0]; v.Switch != "access" || v.Port != "ge-0/0/5" {
		t.Errorf("VM placed at %s %s, want access ge-0/0/5", v.Switch, v.Port)
	}
}

func TestBuildToleratesFailedSwitches(t *testing.T) {
	sw, arp := topology()
	got := Build([]*collect.Switch{nil, sw[1], nil}, arp, Options{AllPorts: true})
	if len(got) == 0 {
		t.Fatal("no rows")
	}
	for _, e := range got {
		if e.Switch != "access" {
			t.Errorf("row from a failed switch: %+v", e)
		}
	}
}

func TestNormName(t *testing.T) {
	for in, want := range map[string]string{
		"Access.Lab.Example": "access", "core-sw(FOC1234X0YZ)": "core-sw", " 10.0.0.3 ": "10.0.0.3", "": "",
	} {
		if got := NormName(in); got != want {
			t.Errorf("NormName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNaturalLess(t *testing.T) {
	in := []string{"Gi1/0/10", "Gi1/0/2", "Gi1/0/1", "Te1/1/1", "Gi2/0/1", "bridge port 9", "Gi1/0/02"}
	got := sorted(in)
	want := "Gi1/0/1,Gi1/0/2,Gi1/0/02,Gi1/0/10,Gi2/0/1,Te1/1/1,bridge port 9"
	if strings.Join(got, ",") != want {
		t.Errorf("natural order = %v", got)
	}
}

func TestDot1xName(t *testing.T) {
	if Dot1xName(2) != "auto" || Dot1xName(1) != "force-unauthorized" || Dot1xName(3) != "force-authorized" || Dot1xName(9) != "unknown(9)" {
		t.Error("Dot1xName wrong")
	}
}

func sorted(v []string) []string {
	out := append([]string(nil), v...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && NaturalLess(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func keys(m map[string][]Entry) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return sorted(out)
}

// A LAG: LLDP is heard on the members, the FDB lives on the aggregate.
func TestNeighbourOnLAGMemberMarksAggregate(t *testing.T) {
	core := &collect.Switch{Target: "10.0.0.2", SysName: "core",
		Interfaces: map[int]*collect.Interface{5: iface(5, "Gi1/0/5", 1)}, BridgePortIfIndex: map[int]int{5: 5}}
	access := &collect.Switch{Target: "10.0.0.3", SysName: "access",
		Interfaces: map[int]*collect.Interface{
			47: iface(47, "ge-0/0/47", 1), 48: iface(48, "ge-0/0/48", 1),
			100: {IfIndex: 100, Name: "ae0", Type: 161, Admin: 1, Oper: 1},
		},
		BridgePortIfIndex: map[int]int{100: 100},
		Stack:             map[int][]int{47: {100}, 48: {100}},
		Neighbors: []collect.Neighbor{
			{IfIndex: 47, Protocol: "lldp", SysName: "core"}, {IfIndex: 48, Protocol: "lldp", SysName: "core"},
		},
	}
	// Four devices behind an unmanaged switch on core Gi1/0/5 (12 MACs there), also learned on ae0.
	for i := 0; i < 12; i++ {
		core.FDB = append(core.FDB, collect.FDBEntry{MAC: net.HardwareAddr{0, 1, 2, 3, 4, byte(i)}, BridgePort: 5, VLAN: 10})
	}
	for i := 0; i < 4; i++ {
		access.FDB = append(access.FDB, collect.FDBEntry{MAC: net.HardwareAddr{0, 1, 2, 3, 4, byte(i)}, BridgePort: 100, VLAN: 10})
	}
	got := Build([]*collect.Switch{core, access}, nil, Options{UplinkThreshold: 0, AllPorts: true})
	members := 0
	for _, e := range got {
		if e.MAC != "" && e.Switch != "core" {
			t.Errorf("device placed on %s %s", e.Switch, e.Port)
		}
		if e.Switch == "access" && e.Port == "ae0" && e.UplinkKind != "switch" {
			t.Errorf("ae0 not an uplink: %+v", e)
		}
		if e.MemberOf == "ae0" {
			members++
		}
	}
	if members != 2 {
		t.Errorf("member rows with member_of=ae0: %d", members)
	}
}

// Junos: the logical unit ge-0/0/5.0 is the bridge port; the physical ge-0/0/5 is not listed apart.
func TestJunosUnitStandsForPhysicalPort(t *testing.T) {
	s := &collect.Switch{Target: "10.0.0.3", SysName: "ex",
		Interfaces: map[int]*collect.Interface{
			510: iface(510, "ge-0/0/5", 1), 520: {IfIndex: 520, Name: "ge-0/0/5.0", Type: 53, Admin: 1, Oper: 1},
			511: iface(511, "ge-0/0/6", 2), 521: {IfIndex: 521, Name: "ge-0/0/6.0", Type: 53, Admin: 1, Oper: 2},
		},
		BridgePortIfIndex: map[int]int{1: 520, 2: 521},
		Stack:             map[int][]int{510: {520}, 511: {521}},
		FDB:               []collect.FDBEntry{{MAC: mac(mA), BridgePort: 1, VLAN: 10}},
	}
	var ports []string
	for _, e := range Build([]*collect.Switch{s}, nil, Options{AllPorts: true}) {
		ports = append(ports, e.Port)
	}
	if strings.Join(sorted(ports), ",") != "ge-0/0/5.0,ge-0/0/6.0" {
		t.Errorf("ports %v", ports)
	}
}

// A pruned trunk: counting MACs per VLAN keeps VMs on the hypervisor port.
func TestPerVLANCountOnPrunedTrunk(t *testing.T) {
	core := &collect.Switch{Target: "10.0.0.2", SysName: "core",
		Interfaces: map[int]*collect.Interface{1: iface(1, "Gi1/0/1", 1)}, BridgePortIfIndex: map[int]int{1: 1}}
	access := &collect.Switch{Target: "10.0.0.3", SysName: "access",
		Interfaces: map[int]*collect.Interface{48: iface(48, "ge-0/0/48", 1)}, BridgePortIfIndex: map[int]int{48: 48}}
	vm := func(i int) net.HardwareAddr { return net.HardwareAddr{2, 0, 0, 0, 0, byte(i)} }
	for i := 0; i < 15; i++ { // VMs in VLANs 10-13 on the hypervisor
		core.FDB = append(core.FDB, collect.FDBEntry{MAC: vm(i), BridgePort: 1, VLAN: 10 + i%4})
	}
	for i := 15; i < 20; i++ { // five VLAN-30 VMs, also seen across the VLAN-30-only trunk
		core.FDB = append(core.FDB, collect.FDBEntry{MAC: vm(i), BridgePort: 1, VLAN: 30})
		access.FDB = append(access.FDB, collect.FDBEntry{MAC: vm(i), BridgePort: 48, VLAN: 30})
	}
	access.FDB = append(access.FDB, collect.FDBEntry{MAC: mac("00:1b:63:00:00:99"), BridgePort: 48, VLAN: 30}) // the firewall
	for _, e := range Build([]*collect.Switch{core, access}, nil, Options{}) {
		if strings.HasPrefix(e.MAC, "02:") && e.Switch != "core" {
			t.Errorf("VM %s placed on %s %s", e.MAC, e.Switch, e.Port)
		}
	}
}

func TestAmbiguousSysNameIsNotProof(t *testing.T) {
	a := &collect.Switch{Target: "10.0.0.2", SysName: "Switch",
		Interfaces: map[int]*collect.Interface{10: iface(10, "Gi1/0/10", 1)}, BridgePortIfIndex: map[int]int{10: 10},
		Neighbors: []collect.Neighbor{{IfIndex: 10, Protocol: "cdp", SysName: "Switch"}}}
	b := &collect.Switch{Target: "10.0.0.3", SysName: "Switch",
		Interfaces: map[int]*collect.Interface{1: iface(1, "Po1", 1)}, BridgePortIfIndex: map[int]int{1: 1}}
	a.FDB = []collect.FDBEntry{{MAC: mac(mA), BridgePort: 10, VLAN: 1}}
	b.FDB = []collect.FDBEntry{{MAC: mac(mA), BridgePort: 1, VLAN: 1}, {MAC: mac(mB), BridgePort: 1, VLAN: 1}}
	for _, e := range Build([]*collect.Switch{a, b}, nil, Options{}) {
		if e.UplinkKind == "switch" {
			t.Errorf("ambiguous name treated as proof: %+v", e)
		}
	}
}

func TestPVIDGuessCorrectedFromOtherSwitch(t *testing.T) {
	sw, arp := topology()
	got := byMAC(Build(sw, arp, Options{}))
	if c := got[mC][0]; c.VLAN != 20 || c.VLANSource != "fdb-other-switch" {
		t.Errorf("phone VLAN %d source %q", c.VLAN, c.VLANSource)
	}
	if e := got[mE][0]; e.VLANSource != "" || e.VLAN != 0 {
		t.Errorf("unknown VLAN: %+v", e)
	}
	if a := got[mA][0]; a.VLANSource != "fdb" {
		t.Errorf("Q-BRIDGE VLAN source %q", a.VLANSource)
	}
}

func TestManagementIPIdentityViaResolvedAddress(t *testing.T) {
	sw, arp := topology()
	core, access := sw[0], sw[1]
	core.Neighbors, access.Neighbors, core.BaseMAC, access.BaseMAC = nil, nil, nil, nil
	core.Target, core.Addr = "core-sw.lab:161", "10.0.0.2" // hostname target, dialled address recorded
	access.FDB = append(access.FDB, collect.FDBEntry{MAC: mac("00:00:0c:dd:dd:dd"), BridgePort: 24})
	arp = append(arp, collect.ARPEntry{IP: net.ParseIP("10.0.0.2"), MAC: mac("00:00:0c:dd:dd:dd")})
	if u := byMAC(Build(sw, arp, Options{}))["00:00:0c:dd:dd:dd"][0]; u.UplinkReason != "faces core" {
		t.Errorf("uplink via resolved management IP: %+v", u)
	}
}

// routerOnAStick: one switch whose trunk Gi1/0/48 (tagged 50 and 60, native 1) leads to a router
// answering on both VLANs with one MAC, and access ports in each VLAN.
func routerOnAStick() *collect.Switch {
	const rtr = "00:15:17:00:00:01"
	return &collect.Switch{
		Target: "10.0.0.2", SysName: "sw",
		Interfaces: map[int]*collect.Interface{
			1: iface(1, "Gi1/0/1", 1), 2: iface(2, "Gi1/0/2", 1), 3: iface(3, "Gi1/0/3", 2), 48: iface(48, "Gi1/0/48", 1),
		},
		BridgePortIfIndex: map[int]int{1: 1, 2: 2, 3: 3, 48: 48},
		PVID:              map[int]int{1: 50, 2: 60, 3: 60, 48: 1},
		Egress:            map[int][]int{1: {50}, 2: {60}, 3: {60}, 48: {1, 50, 60}},
		Untagged:          map[int][]int{1: {50}, 2: {60}, 3: {60}, 48: {1}},
		VLANNames:         map[int]string{60: "quarantine"},
		FDB: []collect.FDBEntry{
			{MAC: mac(rtr), BridgePort: 48, VLAN: 50, Status: collect.FDBLearned},
			{MAC: mac(rtr), BridgePort: 48, VLAN: 60, Status: collect.FDBLearned},
			{MAC: mac(mA), BridgePort: 1, VLAN: 50, Status: collect.FDBLearned}, // this machine
			{MAC: mac(mB), BridgePort: 2, VLAN: 60, Status: collect.FDBLearned},
			{MAC: mac(mD), BridgePort: 2, VLAN: 60, Status: collect.FDBLearned},
			{MAC: mac(mC), BridgePort: 2, VLAN: 60, Status: collect.FDBLearned},
		},
	}
}

func rowsOf(entries []Entry, m string) map[int]Entry {
	out := map[int]Entry{}
	for _, e := range entries {
		if e.MAC == m {
			out[e.VLAN] = e
		}
	}
	return out
}

func TestIPsJoinPerVLAN(t *testing.T) {
	const rtr = "00:15:17:00:00:01"
	ip := func(s string) net.IP { return net.ParseIP(s) }
	for _, tc := range []struct {
		name      string
		arp       []collect.ARPEntry
		own       map[string]net.HardwareAddr
		want50    string
		want60    string
		other50   string
		other60   string
		wantB     string // the VLAN 60 host's IPs
		wantBySrc string // VLANBy of the router binding after resolution
	}{
		{
			name:   "local cache placed by this machine's own MAC",
			arp:    []collect.ARPEntry{{IP: ip("10.50.0.1"), MAC: mac(rtr), Iface: "eth0", Source: collect.LocalSource}},
			own:    map[string]net.HardwareAddr{"eth0": mac(mA)},
			want50: "10.50.0.1", want60: "",
		},
		{
			name: "router ARP placed by its VLAN interface name, both VLANs",
			arp: []collect.ARPEntry{
				{IP: ip("10.50.0.1"), MAC: mac(rtr), IfIndex: 150, Iface: "Vlan50", Source: "rtr", VLAN: 50, VLANBy: "ifname"},
				{IP: ip("10.60.0.1"), MAC: mac(rtr), IfIndex: 160, Iface: "Vlan60", Source: "rtr", VLAN: 60, VLANBy: "ifname"},
				{IP: ip("10.60.0.9"), MAC: mac(mB), IfIndex: 160, Iface: "Vlan60", Source: "rtr", VLAN: 60, VLANBy: "ifname"},
			},
			want50: "10.50.0.1", want60: "10.60.0.1", wantB: "10.60.0.9",
		},
		{
			name: "FDB vote overrides a wrong interface name",
			arp: []collect.ARPEntry{
				{IP: ip("10.60.0.1"), MAC: mac(rtr), IfIndex: 7, Iface: "vlan50", Source: "rtr", VLAN: 50, VLANBy: "ifname"},
				{IP: ip("10.60.0.9"), MAC: mac(mB), IfIndex: 7, Iface: "vlan50", Source: "rtr", VLAN: 50, VLANBy: "ifname"},
				{IP: ip("10.60.0.8"), MAC: mac(mD), IfIndex: 7, Iface: "vlan50", Source: "rtr", VLAN: 50, VLANBy: "ifname"},
				{IP: ip("10.60.0.7"), MAC: mac(mC), IfIndex: 7, Iface: "vlan50", Source: "rtr", VLAN: 50, VLANBy: "ifname"},
			},
			want50: "", want60: "10.60.0.1", wantB: "10.60.0.9",
		},
		{
			name:    "unknown VLAN on a multi-VLAN MAC is not shown as the row's address",
			arp:     []collect.ARPEntry{{IP: ip("10.50.0.1"), MAC: mac(rtr), Source: "rtr"}},
			other50: "10.50.0.1 (VLAN ?)", other60: "10.50.0.1 (VLAN ?)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Build([]*collect.Switch{routerOnAStick()}, tc.arp, Options{LocalMACs: tc.own})
			r := rowsOf(got, rtr)
			if len(r) != 2 {
				t.Fatalf("router rows: %+v", r)
			}
			for _, c := range []struct {
				vlan        int
				ips, others string
			}{{50, tc.want50, tc.other50}, {60, tc.want60, tc.other60}} {
				e := r[c.vlan]
				if strings.Join(e.IPs, ",") != c.ips || strings.Join(e.OtherIPs, ",") != c.others {
					t.Errorf("VLAN %d: ips %v other %v; want %q / %q", c.vlan, e.IPs, e.OtherIPs, c.ips, c.others)
				}
				if e.PortMode != "trunk" || e.NativeVLAN != 1 || e.TaggedVLANs != "50,60" {
					t.Errorf("VLAN %d trunk fields: %q native %d tagged %q", c.vlan, e.PortMode, e.NativeVLAN, e.TaggedVLANs)
				}
			}
			if tc.wantB != "" {
				if b := rowsOf(got, mB)[60]; strings.Join(b.IPs, ",") != tc.wantB {
					t.Errorf("host B: %v", b.IPs)
				}
			}
		})
	}
}

// A MAC's VLAN 50 entry has aged out and only its VLAN 60 entry remains: a binding known to be
// in VLAN 50 must not become the VLAN 60 row's address.
func TestIPKnownInAnAgedOutVLAN(t *testing.T) {
	const rtr = "00:15:17:00:00:01"
	s := routerOnAStick()
	s.FDB = s.FDB[1:] // drop the router's VLAN 50 entry
	arp := []collect.ARPEntry{{IP: net.ParseIP("10.50.0.1"), MAC: mac(rtr), Source: "rtr", VLAN: 50, VLANBy: "ifname"}}
	e := rowsOf(Build([]*collect.Switch{s}, arp, Options{}), rtr)[60]
	if len(e.IPs) != 0 || strings.Join(e.OtherIPs, ",") != "10.50.0.1 (VLAN 50)" {
		t.Errorf("ips %v other %v", e.IPs, e.OtherIPs)
	}
	// A binding with no VLAN on a MAC with one VLAN keeps the old behaviour: it is the address.
	arp[0].VLAN, arp[0].VLANBy = 0, ""
	e = rowsOf(Build([]*collect.Switch{s}, arp, Options{}), rtr)[60]
	if strings.Join(e.IPs, ",") != "10.50.0.1" || len(e.OtherIPs) != 0 {
		t.Errorf("single-VLAN MAC, unknown binding VLAN: ips %v other %v", e.IPs, e.OtherIPs)
	}
}

func TestEmptyPortsShowConfiguredVLAN(t *testing.T) {
	s := routerOnAStick()
	var gi3 *Entry
	for _, e := range Build([]*collect.Switch{s}, nil, Options{AllPorts: true}) {
		if e.Port == "Gi1/0/3" {
			e := e
			gi3 = &e
		}
	}
	if gi3 == nil || gi3.VLAN != 60 || gi3.VLANSource != "port" || gi3.VLANName != "quarantine" || gi3.PortMode != "access" || gi3.NativeVLAN != 0 {
		t.Fatalf("Gi1/0/3: %+v", gi3)
	}
	// No membership table: the PVID is shown as a guess.
	s.Egress, s.Untagged = map[int][]int{}, map[int][]int{}
	for _, e := range Build([]*collect.Switch{s}, nil, Options{AllPorts: true}) {
		if e.Port == "Gi1/0/3" && (e.VLAN != 60 || e.VLANSource != "pvid" || e.PortMode != "") {
			t.Errorf("without membership: %+v", e)
		}
	}
}

func TestVLANRanges(t *testing.T) {
	for in, want := range map[string]string{"": "", "5": "5", "1,2": "1,2", "1,2,3": "1-3", "1,2,3,7,9,10,11,12": "1-3,7,9-12", "50,60": "50,60"} {
		var v []int
		for _, f := range strings.Split(in, ",") {
			if f != "" {
				n := 0
				for _, c := range f {
					n = n*10 + int(c-'0')
				}
				v = append(v, n)
			}
		}
		if got := vlanRanges(v); got != want {
			t.Errorf("vlanRanges(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestIPJoinEdgeCases(t *testing.T) {
	const rtr = "00:15:17:00:00:01"
	s := routerOnAStick()
	// The same binding from two sources, one of which knows its VLAN: no "(VLAN ?)" echo.
	arp := []collect.ARPEntry{
		{IP: net.ParseIP("10.50.0.1"), MAC: mac(rtr), Source: "rtr", IfIndex: 150, Iface: "Vlan50", VLAN: 50, VLANBy: "ifname"},
		{IP: net.ParseIP("10.50.0.1"), MAC: mac(rtr), Source: "other"},
	}
	r := rowsOf(Build([]*collect.Switch{s}, arp, Options{}), rtr)
	if strings.Join(r[50].IPs, ",") != "10.50.0.1" || len(r[60].IPs)+len(r[60].OtherIPs)+len(r[50].OtherIPs) != 0 {
		t.Errorf("rows %+v", r)
	}
	// One other address is not enough to overrule an interface name; two are.
	one := []collect.ARPEntry{
		{IP: net.ParseIP("10.50.0.1"), MAC: mac(rtr), Source: "rtr", IfIndex: 7, Iface: "vlan50", VLAN: 50, VLANBy: "ifname"},
		{IP: net.ParseIP("10.60.0.9"), MAC: mac(mB), Source: "rtr", IfIndex: 7, Iface: "vlan50", VLAN: 50, VLANBy: "ifname"},
	}
	if r := rowsOf(Build([]*collect.Switch{s}, one, Options{}), rtr); strings.Join(r[50].IPs, ",") != "10.50.0.1" {
		t.Errorf("one voter overruled the name: %+v", r)
	}
	// A row whose VLAN is only a PVID guess keeps every address.
	bridge := &collect.Switch{Target: "10.0.0.3", SysName: "acc",
		Interfaces:        map[int]*collect.Interface{1: iface(1, "p1", 1)},
		BridgePortIfIndex: map[int]int{1: 1}, PVID: map[int]int{1: 20},
		FDB: []collect.FDBEntry{{MAC: mac(mB), BridgePort: 1}}}
	got := Build([]*collect.Switch{bridge}, []collect.ARPEntry{{IP: net.ParseIP("10.0.30.6"), MAC: mac(mB), VLAN: 30, VLANBy: "ifname"}}, Options{})
	if len(got) != 1 || got[0].VLANSource != "pvid" || strings.Join(got[0].IPs, ",") != "10.0.30.6" {
		t.Errorf("pvid row: %+v", got)
	}
}

// An interface whose addresses sit in different VLANs (a flat router port facing a VLAN
// mismatch, or a synthetic lab) cannot place any of them.
func TestMixedInterfaceDoesNotVote(t *testing.T) {
	s := routerOnAStick()
	arp := []collect.ARPEntry{
		{IP: net.ParseIP("10.50.0.5"), MAC: mac(mA), Source: "rtr", IfIndex: 3},
		{IP: net.ParseIP("10.60.0.9"), MAC: mac(mB), Source: "rtr", IfIndex: 3},
	}
	got := Build([]*collect.Switch{s}, arp, Options{})
	if a, b := rowsOf(got, mA)[50], rowsOf(got, mB)[60]; strings.Join(a.IPs, ",") != "10.50.0.5" || strings.Join(b.IPs, ",") != "10.60.0.9" {
		t.Errorf("A %v %v, B %v %v", a.IPs, a.OtherIPs, b.IPs, b.OtherIPs)
	}
}

// SG350-style agent: dot1qPvid is 1 on every port while VLAN membership is right. A trunk's
// native VLAN and an access port's VLAN come from membership.
func TestMembershipBeatsBogusPVID(t *testing.T) {
	s := &collect.Switch{Target: "10.0.0.4", SysName: "sg350",
		Interfaces:        map[int]*collect.Interface{1: iface(1, "gi1", 1), 25: iface(25, "gi25", 1)},
		BridgePortIfIndex: map[int]int{1: 1, 25: 25},
		PVID:              map[int]int{1: 1, 25: 1},
		Egress:            map[int][]int{1: {400}, 25: {1, 400, 3999}},
		Untagged:          map[int][]int{1: {400}, 25: {3999}},
		FDB:               []collect.FDBEntry{{MAC: mac(mB), BridgePort: 1}}, // BRIDGE-MIB: no VLAN
	}
	for _, e := range Build([]*collect.Switch{s}, nil, Options{AllPorts: true}) {
		switch e.Port {
		case "gi1":
			if e.VLAN != 400 || e.VLANSource != "port" {
				t.Errorf("gi1: vlan %d from %q", e.VLAN, e.VLANSource)
			}
		case "gi25":
			if e.PortMode != "trunk" || e.NativeVLAN != 3999 || e.TaggedVLANs != "1,400" {
				t.Errorf("gi25: %q native %d tagged %q", e.PortMode, e.NativeVLAN, e.TaggedVLANs)
			}
		}
	}
}

func TestNeighbourSwitchMACIsLabelled(t *testing.T) {
	sw, arp := topology()
	for _, e := range Build(sw, arp, Options{}) {
		if e.MAC == mAcc && e.SwitchMAC != "access" {
			t.Errorf("access switch's MAC row: %+v", e)
		}
		if e.MAC == mA && e.SwitchMAC != "" {
			t.Errorf("host labelled as a switch: %+v", e)
		}
	}
}

func TestHybridPortKeepsItsUntaggedVLANs(t *testing.T) {
	s := &collect.Switch{Target: "10.0.0.5", SysName: "h3c",
		Interfaces:        map[int]*collect.Interface{1: iface(1, "GE1/0/1", 2)},
		BridgePortIfIndex: map[int]int{1: 1}, PVID: map[int]int{1: 30},
		Egress: map[int][]int{1: {10, 20, 30, 40}}, Untagged: map[int][]int{1: {30, 40}}}
	e := Build([]*collect.Switch{s}, nil, Options{AllPorts: true})[0]
	if e.PortMode != "hybrid" || e.UntaggedVLANs != "30,40" || e.TaggedVLANs != "10,20" || e.NativeVLAN != 30 {
		t.Errorf("%+v", e)
	}
}

// A Cisco per-VLAN instance numbers its own bridge ports: membership must use the default
// instance's number for the port.
func TestPerVLANInstanceUsesDefaultBridgePort(t *testing.T) {
	s := &collect.Switch{Target: "10.0.0.6", SysName: "cat",
		Interfaces:        map[int]*collect.Interface{10101: iface(10101, "Gi1/0/1", 1), 10102: iface(10102, "Gi1/0/2", 1)},
		BridgePortIfIndex: map[int]int{1: 10101, 2: 10102}, PVID: map[int]int{1: 10, 2: 20},
		Egress: map[int][]int{1: {10}, 2: {10, 20}}, Untagged: map[int][]int{1: {10}, 2: {20}},
		FDB: []collect.FDBEntry{{MAC: mac(mA), BridgePort: 2, IfIndex: 10101, VLAN: 10}}} // instance bp 2 is Gi1/0/1
	e := byMAC(Build([]*collect.Switch{s}, nil, Options{}))[mA][0]
	if e.Port != "Gi1/0/1" || e.BridgePort != 1 || e.PortMode != "access" {
		t.Errorf("%+v", e)
	}
}

// A VLAN-less forwarding entry on an SG350-style trunk (PVID 1, untagged 3999) takes the native
// VLAN from membership.
func TestVLANLessTrunkRowUsesMembershipNative(t *testing.T) {
	s := &collect.Switch{Target: "10.0.0.4", SysName: "sg350",
		Interfaces:        map[int]*collect.Interface{25: iface(25, "gi25", 1)},
		BridgePortIfIndex: map[int]int{25: 25}, PVID: map[int]int{25: 1},
		Egress: map[int][]int{25: {1, 400, 3999}}, Untagged: map[int][]int{25: {3999}},
		FDB: []collect.FDBEntry{{MAC: mac(mB), BridgePort: 25}}}
	e := byMAC(Build([]*collect.Switch{s}, nil, Options{}))[mB][0]
	if e.VLAN != 3999 || e.VLANSource != "pvid" || e.NativeVLAN != 3999 {
		t.Errorf("%+v", e)
	}
}

func TestResolveARPVLANsIsLinear(t *testing.T) {
	const n = 20000
	arp := make([]collect.ARPEntry, n)
	auth := map[string]map[int]bool{}
	for i := range arp {
		m := net.HardwareAddr{2, 0, 0, byte(i >> 16), byte(i >> 8), byte(i)}
		arp[i] = collect.ARPEntry{IP: net.IPv4(10, 50, byte(i>>8), byte(i)), MAC: m, IfIndex: 7, Iface: "Vlan50", Source: "core", VLAN: 50, VLANBy: "ifname"}
		auth[m.String()] = map[int]bool{50: true}
	}
	start := time.Now()
	out := resolveARPVLANs(arp, auth, nil)
	if d := time.Since(start); d > 2*time.Second || out[n-1].VLAN != 50 {
		t.Errorf("%d bindings took %v (vlan %d)", n, d, out[n-1].VLAN)
	}
}
