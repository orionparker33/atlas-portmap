// Command demoreport writes a realistic, deterministic atlas-portmap report for UI work and
// screenshots: a core switch and two access switches at a fictional site, built through the
// real join (portmap.Build) and vendor database, so it exercises the same code as a scan.
//
//	go run ./tools/demoreport > demo.json
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/output"
	"github.com/orionparker33/atlas-portmap/internal/portmap"
	"github.com/orionparker33/atlas-portmap/internal/vendordb"
)

type kind struct {
	oui   [3]byte
	vlan  int
	ipNet string
	phone bool
	ap    bool
	cam   bool
}

var kinds = []kind{
	{oui: [3]byte{0x00, 0x14, 0x22}, vlan: 10, ipNet: "10.10.10"},              // Dell
	{oui: [3]byte{0x3c, 0x52, 0x82}, vlan: 10, ipNet: "10.10.10"},              // HP
	{oui: [3]byte{0x00, 0x1b, 0x63}, vlan: 10, ipNet: "10.10.10"},              // Apple
	{oui: [3]byte{0x54, 0xee, 0x75}, vlan: 10, ipNet: "10.10.10"},              // Wistron (laptops)
	{oui: [3]byte{0x00, 0x04, 0xf2}, vlan: 20, ipNet: "10.10.20", phone: true}, // Polycom
	{oui: [3]byte{0x00, 0x80, 0x77}, vlan: 10, ipNet: "10.10.10"},              // Brother printers
	{oui: [3]byte{0x00, 0x40, 0x8c}, vlan: 40, ipNet: "10.10.40", cam: true},   // Axis cameras
}

func main() {
	rng := rand.New(rand.NewSource(7))
	db, err := vendordb.Default()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var arp []collect.ARPEntry
	serial := 0
	mac := func(o [3]byte) net.HardwareAddr {
		serial++
		return net.HardwareAddr{o[0], o[1], o[2], byte(serial >> 8), byte(serial), byte(rng.Intn(256))}
	}
	host := map[string]int{}
	addIP := func(m net.HardwareAddr, n string) {
		host[n]++
		arp = append(arp, collect.ARPEntry{IP: net.ParseIP(fmt.Sprintf("%s.%d", n, 20+host[n])), MAC: m})
	}
	mkSwitch := func(target, name, descr, oid string, base net.HardwareAddr, ports int, prefix string) *collect.Switch {
		s := &collect.Switch{Target: target, SysName: name, SysDescr: descr, SysObjectID: oid, Enterprise: 11, BaseMAC: base,
			Interfaces: map[int]*collect.Interface{}, BridgePortIfIndex: map[int]int{}, PVID: map[int]int{},
			Egress: map[int][]int{}, Untagged: map[int][]int{},
			VLANNames: map[int]string{1: "default", 10: "users", 20: "voice", 30: "servers", 40: "cameras", 99: "mgmt"},
			Dot1x:     map[int]int{}, Extra: map[string]map[int]string{}, LLDPSeen: true, FDBSource: "q-bridge"}
		for i := 1; i <= ports; i++ {
			oper, admin := 1, 1
			switch r := rng.Intn(100); {
			case r < 18:
				oper = 2
			case r < 21:
				admin, oper = 2, 2
			}
			s.Interfaces[i] = &collect.Interface{IfIndex: i, Name: fmt.Sprintf("%s%d", prefix, i), Descr: fmt.Sprintf("%s%d", prefix, i), Type: 6, Admin: admin, Oper: oper, SpeedMbps: 1000}
			s.BridgePortIfIndex[i] = i
			s.PVID[i] = 10
		}
		return s
	}
	core := mkSwitch("10.10.99.2", "core-01", "Aruba JL322A 2930M-48G-PoE+ Switch, revision WC.16.11", "1.3.6.1.4.1.11.2.3.7.11.181", net.HardwareAddr{0x94, 0x18, 0x82, 0, 0, 1}, 28, "1/")
	acc1 := mkSwitch("10.10.99.3", "access-01", "Aruba JL261A 2930F-24G-PoE+ Switch", "1.3.6.1.4.1.11.2.3.7.11.172", net.HardwareAddr{0x94, 0x18, 0x82, 0, 0, 2}, 48, "1/")
	acc2 := mkSwitch("10.10.99.4", "access-02", "Aruba JL261A 2930F-24G-PoE+ Switch", "1.3.6.1.4.1.11.2.3.7.11.172", net.HardwareAddr{0x94, 0x18, 0x82, 0, 0, 3}, 24, "1/")
	for _, s := range []*collect.Switch{core, acc1, acc2} {
		arp = append(arp, collect.ARPEntry{IP: net.ParseIP(s.Target), MAC: s.BaseMAC})
	}
	up := func(s *collect.Switch, i int) { s.Interfaces[i].Admin, s.Interfaces[i].Oper = 1, 1 }
	// Uplinks: core 1/25 -> access-01 1/48, core 1/26 -> access-02 1/24 (LLDP both ways).
	link := func(a *collect.Switch, ai int, b *collect.Switch, bi int) {
		up(a, ai)
		up(b, bi)
		a.Interfaces[ai].Alias = "uplink " + b.SysName
		b.Interfaces[bi].Alias = "uplink " + a.SysName
		a.Neighbors = append(a.Neighbors, collect.Neighbor{IfIndex: ai, Protocol: "lldp", SysName: b.SysName, PortID: b.Interfaces[bi].Name, Caps: collect.Caps{Bridge: true, Router: true}})
		b.Neighbors = append(b.Neighbors, collect.Neighbor{IfIndex: bi, Protocol: "lldp", SysName: a.SysName, PortID: a.Interfaces[ai].Name, Caps: collect.Caps{Bridge: true, Router: true}})
		a.PVID[ai], b.PVID[bi] = 99, 99
	}
	link(core, 25, acc1, 48)
	link(core, 26, acc2, 24)
	// access-01's uplink is an HP-style trunk: Trk1 over 1/47 and 1/48 holds the FDB entries, and
	// LLDP is heard on the members.
	up(acc1, 47)
	acc1.Interfaces[100] = &collect.Interface{IfIndex: 100, Name: "Trk1", Descr: "Trk1", Type: 161, Admin: 1, Oper: 1, SpeedMbps: 2000}
	acc1.Stack = map[int][]int{47: {100}, 48: {100}}
	delete(acc1.BridgePortIfIndex, 47)
	delete(acc1.BridgePortIfIndex, 48)
	acc1.BridgePortIfIndex[100] = 100
	acc1.PVID[100] = 99
	acc1.Interfaces[47].Alias = "uplink core-01 (Trk1)"
	acc1.Interfaces[48].Alias = "uplink core-01 (Trk1)"
	acc1.Neighbors = append(acc1.Neighbors, collect.Neighbor{IfIndex: 47, Protocol: "lldp", SysName: core.SysName, PortID: "1/27", Caps: collect.Caps{Bridge: true, Router: true}})
	acc1.FDB = append(acc1.FDB, collect.FDBEntry{MAC: core.BaseMAC, BridgePort: 100, VLAN: 99, Status: collect.FDBLearned})
	learn := func(s *collect.Switch, port, vlan int, m net.HardwareAddr) {
		s.FDB = append(s.FDB, collect.FDBEntry{MAC: m, BridgePort: port, VLAN: vlan, Status: collect.FDBLearned})
	}
	upstream := map[*collect.Switch]int{acc1: 25, acc2: 26}
	upstreamPort := map[*collect.Switch]int{acc1: 47, acc2: 24} // first uplink port on the access switch
	place := func(s *collect.Switch, port int, k kind) {
		m := mac(k.oui)
		addIP(m, k.ipNet)
		learn(s, port, k.vlan, m)
		if up, ok := upstream[s]; ok {
			learn(core, up, k.vlan, m)
		}
	}
	// Servers and VMs on the core.
	for i := 1; i <= 12; i++ {
		if core.Interfaces[i].Oper != 1 {
			continue
		}
		core.Interfaces[i].Alias = fmt.Sprintf("srv-%02d", i)
		core.PVID[i] = 30
		m := mac([3]byte{0x00, 0x50, 0x56})
		addIP(m, "10.10.30")
		learn(core, i, 30, m)
		if i%4 == 0 { // hypervisor: several VMs on one port
			for v := 0; v < 5; v++ {
				vm := mac([3]byte{0x02, 0x16, 0x3e})
				addIP(vm, "10.10.30")
				learn(core, i, 30, vm)
			}
			core.Neighbors = append(core.Neighbors, collect.Neighbor{IfIndex: i, Protocol: "lldp", SysName: fmt.Sprintf("hv%d", i/4), Caps: collect.Caps{Bridge: true, Router: true}})
		}
	}
	// Desks on the access switches: phones with PCs behind them, printers, cameras, APs.
	for _, s := range []*collect.Switch{acc1, acc2} {
		for i := 1; i < upstreamPort[s]; i++ {
			if _, bridged := s.BridgePortIfIndex[i]; !bridged || s.Interfaces[i].Oper != 1 || rng.Intn(100) < 12 {
				continue
			}
			k := kinds[rng.Intn(len(kinds))]
			switch {
			case k.phone:
				place(s, i, k)
				place(s, i, kinds[rng.Intn(4)])
				s.Neighbors = append(s.Neighbors, collect.Neighbor{IfIndex: i, Protocol: "lldp", SysName: fmt.Sprintf("SEP%06X", rng.Intn(1<<24)), Platform: "Polycom VVX 450", Caps: collect.Caps{Phone: true, Bridge: true}})
				s.Interfaces[i].Alias = fmt.Sprintf("desk %d", i)
			case k.cam:
				s.PVID[i] = 40
				place(s, i, k)
				s.Interfaces[i].Alias = fmt.Sprintf("camera %d", i)
			default:
				place(s, i, k)
			}
			if rng.Intn(100) < 35 {
				s.Dot1x[i] = 2
			}
		}
	}
	// One access point on access-02 with a dozen randomised client MACs behind it.
	acc2.Interfaces[3].Alias = "AP lobby"
	acc2.Neighbors = append(acc2.Neighbors, collect.Neighbor{IfIndex: 3, Protocol: "lldp", SysName: "ap-lobby", Platform: "Aruba AP-515", Caps: collect.Caps{AP: true, Bridge: true}})
	up(acc2, 3)
	for c := 0; c < 12; c++ {
		m := mac([3]byte{0xda, 0xa1, 0x19})
		addIP(m, "10.10.10")
		learn(acc2, 3, 10, m)
		learn(core, 26, 10, m)
	}
	// The firewall on core 1/28 routes every VLAN with one MAC (router on a stick): each VLAN row
	// gets only that VLAN's gateway address.
	fw := net.HardwareAddr{0x00, 0x09, 0x0f, 0, 0, 1}
	up(core, 28)
	core.Interfaces[28].Alias = "fw-01"
	core.PVID[28] = 99
	for _, v := range []int{10, 20, 30, 40, 99} {
		learn(core, 28, v, fw)
		arp = append(arp, collect.ARPEntry{IP: net.ParseIP(fmt.Sprintf("10.10.%d.1", v)), MAC: fw, IfIndex: 1000 + v,
			Iface: fmt.Sprintf("Vlan%d", v), Source: "10.10.99.1", VLAN: v, VLANBy: "ifname"})
	}
	switches := []*collect.Switch{core, acc1, acc2}
	// VLAN membership: a port sends its PVID untagged and carries tagged whatever else it learned
	// in (a phone's voice VLAN); uplinks and the firewall port are trunks with native VLAN 99.
	trunks := map[*collect.Switch][]int{core: {25, 26, 28}, acc1: {100}, acc2: {24}}
	for _, s := range switches {
		vl := map[int]map[int]bool{}
		for bp := range s.BridgePortIfIndex {
			vl[bp] = map[int]bool{s.PVID[bp]: true}
		}
		for _, bp := range trunks[s] {
			for _, v := range []int{10, 20, 30, 40, 99} {
				vl[bp][v] = true
			}
		}
		for _, e := range s.FDB {
			if vl[e.BridgePort] != nil {
				vl[e.BridgePort][e.VLAN] = true
			}
		}
		for bp, set := range vl {
			for v := range set {
				s.Egress[bp] = append(s.Egress[bp], v)
			}
			sort.Ints(s.Egress[bp])
			s.Untagged[bp] = []int{s.PVID[bp]}
		}
	}
	entries := portmap.Build(switches, arp, portmap.Options{UplinkThreshold: 10, AllPorts: true, Vendor: db.MAC, MACFormat: "colon"})
	rep := output.Report{Tool: "atlas-portmap", Version: "demo", Label: "Contoso – Head office", Generated: time.Date(2026, 10, 27, 9, 15, 0, 0, time.UTC).Format(time.RFC3339), Entries: entries}
	for _, s := range switches {
		_, org := db.Enterprise(s.SysObjectID)
		rep.Switches = append(rep.Switches, output.SwitchSummary{Target: s.Target, Name: s.Name(), Description: s.SysDescr, SysObjectID: s.SysObjectID,
			Vendor: org, FDBSource: s.FDBSource, FDBRows: len(s.FDB), LLDP: true})
	}
	rep.Switches[2].Warnings = []string{"per-VLAN BRIDGE-MIB not readable for VLAN 99 (example warning)"}
	rep.ARPSources = []output.SourceSummary{{Target: "10.10.99.1", Entries: len(arp)}}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
