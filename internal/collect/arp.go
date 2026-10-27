package collect

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/macaddr"
	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
)

// CollectARP reads IP-to-MAC bindings from a router or L3 switch: ipNetToPhysicalTable (IPv4
// and IPv6) and the older ipNetToMediaTable (IPv4). Invalid rows are dropped.
func CollectARP(ctx context.Context, target string, cfg snmpc.Config) ([]ARPEntry, error) {
	sess, err := snmpc.Dial(ctx, target, cfg, 0)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	// One Get before any retries (FirstContact), so wrong credentials cost one attempt, as for a
	// switch. Its answer also says whether the agent's VLAN interface names can be trusted.
	sysOID := ""
	if err := sess.FirstContact(func() error {
		p, ok, err := sess.Get(mib.SysObjectID)
		if ok {
			sysOID = mib.Text(p)
		}
		return err
	}); snmpc.Fatal(err) {
		return nil, sess.Classify(err)
	}
	var out []ARPEntry
	seen := map[string]bool{}
	add := func(ifx int, ip net.IP, mac net.HardwareAddr) {
		if !macaddr.Usable(mac) || ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return
		}
		k := strconv.Itoa(ifx) + "|" + ip.String() + "|" + mac.String() // one binding per interface: each may be another VLAN
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, ARPEntry{IP: ip, MAC: mac, IfIndex: ifx, Source: target})
	}
	walk := func(column string) (map[string]gosnmp.SnmpPDU, error) {
		p, err := sess.Walk(column)
		return byIndex(p, column), err
	}
	invalid := func(types map[string]gosnmp.SnmpPDU, idx string) bool {
		if t, ok := types[idx]; ok {
			if n, ok := mib.IntValue(t); ok && n == 2 {
				return true
			}
		}
		return false
	}
	var soft []error
	for _, table := range []struct {
		addr, typ string
		index     func([]uint32) (int, net.IP, error)
	}{
		{mib.IpNetToPhysicalPhysAddress, mib.IpNetToPhysicalType, mib.NetToPhysicalIndex},
		{mib.IpNetToMediaPhysAddress, mib.IpNetToMediaType, mib.NetToMediaIndex},
	} {
		addrs, err := walk(table.addr)
		if err != nil {
			if snmpc.Fatal(err) && len(addrs) == 0 && len(out) == 0 {
				return nil, sess.Classify(err)
			}
			soft = append(soft, err)
		}
		types, _ := walk(table.typ)
		for idx, p := range addrs {
			if invalid(types, idx) {
				continue
			}
			v, err := mib.Ints(idx)
			if err != nil {
				continue
			}
			ifx, ip, err := table.index(v)
			if err != nil {
				continue
			}
			if mac, ok := mib.MACValue(p); ok {
				add(ifx, ip, mac)
			}
		}
	}
	if len(out) == 0 && len(soft) > 0 {
		return nil, sess.Classify(soft[0])
	}
	nameARPInterfaces(sess, out, !InstanceNamedVLANs(sysOID))
	SortARP(out)
	return out, nil
}

// nameARPInterfaces fills Iface, and (when byName) VLAN where the interface is a VLAN interface
// whose name carries the VLAN ID, for the (few) interfaces the bindings hang off. It stops asking
// at the first fatal error and keeps what it has.
func nameARPInterfaces(sess *snmpc.Session, out []ARPEntry, byName bool) {
	type ifInfo struct {
		name string
		vlan int
	}
	info := map[int]ifInfo{}
	dead := false // no response, authentication failure or cancellation
	get := func(oid string) (gosnmp.SnmpPDU, bool) {
		if dead {
			return gosnmp.SnmpPDU{}, false
		}
		p, ok, err := sess.Get(oid)
		dead = snmpc.Fatal(err)
		return p, ok
	}
	for i := range out {
		ifx := out[i].IfIndex
		if ifx <= 0 {
			continue
		}
		in, ok := info[ifx]
		if !ok && len(info) < 256 {
			var name, descr string
			typ := 0
			if p, ok := get(mib.IfName + "." + strconv.Itoa(ifx)); ok {
				name = mib.Text(p)
			}
			if p, ok := get(mib.IfDescr + "." + strconv.Itoa(ifx)); ok {
				descr = mib.Text(p)
			}
			if p, ok := get(mib.IfType + "." + strconv.Itoa(ifx)); ok {
				if n, ok := mib.IntValue(p); ok {
					typ = int(n)
				}
			}
			in = ifInfo{name: firstNonEmpty(name, descr)}
			if byName {
				if in.vlan = VLANFromIfName(name, typ); in.vlan == 0 {
					in.vlan = VLANFromIfName(descr, typ)
				}
			}
			info[ifx] = in
		}
		out[i].Iface = in.name
		if in.vlan != 0 {
			out[i].VLAN, out[i].VLANBy = in.vlan, "ifname"
		}
	}
}

var vlanIfName = regexp.MustCompile(`(?i)^(?:vlan-interface|vlanif|vlan|vl)?\s*0*([1-9][0-9]{0,3})$`)

// VLANFromIfName reads the VLAN ID from a VLAN interface's name: "50" (Cisco SMB), "Vlan50" or
// "Vl50" (IOS), "VLAN50" or "vlan50" (HPE, Aruba), "Vlanif50" (Huawei), "Vlan-interface50"
// (Comware). Only VLAN interface types count (propVirtual 53, l2vlan 135, l3ipvlan 136). It
// returns 0 when the name says nothing; Junos irb.N and subinterfaces (Gi0/0.60) are left to the
// FDB, since their unit number is a VLAN only by convention.
func VLANFromIfName(name string, ifType int) int {
	switch ifType {
	case 53, 135, 136:
	default:
		return 0
	}
	m := vlanIfName.FindStringSubmatch(strings.TrimSpace(name))
	if m == nil {
		return 0
	}
	v, _ := strconv.Atoi(m[1])
	if v > 4094 {
		return 0
	}
	return v
}

// InstanceNamedVLANs reports agents whose VLAN interface names count instances, not tags:
// RouterOS names them vlan1, vlan2… whatever their VLAN ID, and FreeBSD vlan(4) clones are vlan0,
// vlan1… (OPNsense: vlan01…). Their names say nothing about the VLAN.
func InstanceNamedVLANs(sysObjectID string) bool {
	switch mib.Enterprise(sysObjectID) {
	case 14988, 12325: // MikroTik; FreeBSD bsnmpd (Begemot, pfSense)
		return true
	case 8072: // net-snmp: .3.2.8 is FreeBSD (OPNsense os-net-snmp)
		return mib.Norm(sysObjectID) == "1.3.6.1.4.1.8072.3.2.8"
	}
	return false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// SortARP orders entries by IP (IPv4 before IPv6), then MAC, then interface.
func SortARP(a []ARPEntry) {
	sort.Slice(a, func(i, j int) bool {
		x, y := a[i].IP.To16(), a[j].IP.To16()
		x4, y4 := a[i].IP.To4() != nil, a[j].IP.To4() != nil
		if x4 != y4 {
			return x4
		}
		if c := bytes.Compare(x, y); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(a[i].MAC, a[j].MAC); c != 0 {
			return c < 0
		}
		return a[i].IfIndex < a[j].IfIndex
	})
}
