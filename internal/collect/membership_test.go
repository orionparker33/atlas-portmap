package collect

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/snmptest"
)

// Q-BRIDGE membership is keyed by bridge port, which here differs from the ifIndex: bridge
// ports 1-3 are ifIndexes 101-103. Bridge port 3 is a trunk (tagged 50 and 60, untagged 1), and
// the current table lists the VLANs under two time marks.
func TestMembershipByBridgePort(t *testing.T) {
	a := snmptest.Start(t)
	p := []gosnmp.SnmpPDU{snmptest.Str(mib.SysName, "sw")}
	for bp := 1; bp <= 3; bp++ {
		p = append(p, snmptest.Int(fmt.Sprintf("%s.%d", mib.Dot1dBasePortIfIndex, bp), 100+bp))
	}
	// PortList: first octet's MSB is bridge port 1, so 0x80 = bp1, 0x40 = bp2, 0x20 = bp3.
	for _, r := range []struct {
		mark, vlan       int
		egress, untagged byte
	}{{0, 1, 0x20, 0x20}, {0, 50, 0xa0, 0x80}, {7, 60, 0x60, 0x40}} {
		idx := fmt.Sprintf(".%d.%d", r.mark, r.vlan)
		p = append(p,
			snmptest.Bytes(mib.Dot1qVlanCurrentEgressPorts+idx, []byte{r.egress, 0}),
			snmptest.Bytes(mib.Dot1qVlanCurrentUntaggedPorts+idx, []byte{r.untagged, 0}))
	}
	a.Set("c", p...)
	sw, err := CollectSwitch(context.Background(), a.Addr, testCfg(), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if want := map[int][]int{1: {50}, 2: {60}, 3: {1, 50, 60}}; !reflect.DeepEqual(sw.Egress, want) {
		t.Errorf("egress %v, want %v", sw.Egress, want)
	}
	if want := map[int][]int{1: {50}, 2: {60}, 3: {1}}; !reflect.DeepEqual(sw.Untagged, want) {
		t.Errorf("untagged %v, want %v", sw.Untagged, want)
	}
}

func TestPortList(t *testing.T) {
	// SG300-10 VLAN 60 egress: bridge ports 50 (gi2), 57 and 58 (gi9, gi10).
	b := make([]byte, 128)
	b[6], b[7] = 0x40, 0xc0
	if got := mib.PortList(b); !reflect.DeepEqual(got, []int{50, 57, 58}) {
		t.Errorf("PortList = %v", got)
	}
	if got := mib.PortList(nil); got != nil {
		t.Errorf("PortList(nil) = %v", got)
	}
}

func TestVLANFromIfName(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  int
		want int
	}{
		{"50", 53, 50}, {"Vlan50", 53, 50}, {"Vl50", 136, 50}, {"VLAN50", 53, 50}, {"vlan 7", 135, 7},
		{"Vlanif100", 136, 100}, {"Vlan-interface4094", 136, 4094}, {"vlan0050", 53, 50},
		{"50", 6, 0},         // a physical port named "50"
		{"irb.50", 53, 0},    // Junos unit: a VLAN only by convention
		{"Gi0/0.60", 135, 0}, // subinterface number, not the tag
		{"Vlan4095", 53, 0},  // out of range
		{"Logical-int 1", 22, 0}, {"tunnel1", 131, 0}, {"", 53, 0},
	} {
		if got := VLANFromIfName(c.name, c.typ); got != c.want {
			t.Errorf("VLANFromIfName(%q, %d) = %d, want %d", c.name, c.typ, got, c.want)
		}
	}
}

// The SG300 keeps its one ARP entry on ifIndex 300000, a propVirtual interface named "50".
func TestARPEntriesCarryTheirVLANInterface(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c",
		snmptest.Bytes(mib.IpNetToMediaPhysAddress+".300000.192.168.50.10", net.HardwareAddr{0xbc, 0x24, 0x11, 1, 2, 3}),
		snmptest.Int(mib.IpNetToMediaType+".300000.192.168.50.10", 3),
		snmptest.Str(mib.IfDescr+".300000", "50"), snmptest.Int(mib.IfType+".300000", 53),
	)
	out, err := CollectARP(context.Background(), a.Addr, testCfg())
	if err != nil || len(out) != 1 {
		t.Fatalf("CollectARP: %v %+v", err, out)
	}
	if e := out[0]; e.Iface != "50" || e.VLAN != 50 || e.VLANBy != "ifname" || e.IfIndex != 300000 {
		t.Errorf("entry %+v", e)
	}
}

// RouterOS names VLAN interfaces vlan1, vlan2… by instance: the name must not become the VLAN.
func TestInstanceNamedVLANInterfacesAreNotParsed(t *testing.T) {
	for oid, want := range map[string]bool{
		"1.3.6.1.4.1.14988.1": true, "1.3.6.1.4.1.12325.1.1.2.1.1": true, "1.3.6.1.4.1.8072.3.2.8": true,
		"1.3.6.1.4.1.8072.3.2.10": false, "1.3.6.1.4.1.9.6.1.83.10.1": false, "": false,
	} {
		if got := InstanceNamedVLANs(oid); got != want {
			t.Errorf("InstanceNamedVLANs(%q) = %v", oid, got)
		}
	}
	a := snmptest.Start(t)
	a.Set("c",
		snmptest.OID(mib.SysObjectID, ".1.3.6.1.4.1.14988.1"),
		snmptest.Bytes(mib.IpNetToMediaPhysAddress+".12.10.50.0.9", net.HardwareAddr{0xb8, 0x27, 0xeb, 0, 0, 0x0b}),
		snmptest.Int(mib.IpNetToMediaType+".12.10.50.0.9", 3),
		snmptest.Str(mib.IfName+".12", "vlan1"), snmptest.Int(mib.IfType+".12", 135),
	)
	out, err := CollectARP(context.Background(), a.Addr, testCfg())
	if err != nil || len(out) != 1 || out[0].VLAN != 0 || out[0].Iface != "vlan1" {
		t.Fatalf("CollectARP: %v %+v", err, out)
	}
}

// The same binding on two VLAN interfaces is two bindings: each carries its own VLAN.
func TestARPKeepsOneBindingPerInterface(t *testing.T) {
	a := snmptest.Start(t)
	m := net.HardwareAddr{0, 0x15, 0x17, 0, 0, 1}
	a.Set("c",
		snmptest.Bytes(mib.IpNetToMediaPhysAddress+".150.10.0.0.1", m), snmptest.Bytes(mib.IpNetToMediaPhysAddress+".160.10.0.0.1", m),
		snmptest.Str(mib.IfName+".150", "Vlan50"), snmptest.Int(mib.IfType+".150", 53),
		snmptest.Str(mib.IfName+".160", "Vlan60"), snmptest.Int(mib.IfType+".160", 53),
	)
	out, err := CollectARP(context.Background(), a.Addr, testCfg())
	if err != nil || len(out) != 2 || out[0].VLAN != 50 || out[1].VLAN != 60 {
		t.Fatalf("CollectARP: %v %+v", err, out)
	}
}

// An egress column without its untagged column would make every member look tagged.
func TestIncompleteMembershipIsDropped(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", snmptest.Str(mib.SysName, "sw"), snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 1),
		snmptest.Bytes(mib.Dot1qVlanCurrentEgressPorts+".0.50", []byte{0x80}))
	sw, err := CollectSwitch(context.Background(), a.Addr, testCfg(), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(sw.Egress) != 0 || !hasWarning(sw, "VLAN membership incomplete") {
		t.Errorf("egress %v, warnings %v", sw.Egress, sw.Warnings)
	}
}

func TestJunosIndexBeforeTag(t *testing.T) {
	j := &juniperVLANs{intToTag: map[int]int{2: 1, 3: 2, 4: 3}, tags: map[int]bool{1: true, 2: true, 3: true}}
	for in, want := range map[int]int{2: 1, 3: 2, 4: 3, 7: 7} {
		if got := j.index(in); got != want {
			t.Errorf("index(%d) = %d, want %d", in, got, want)
		}
	}
}
