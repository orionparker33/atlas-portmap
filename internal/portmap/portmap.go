// Package portmap joins switch forwarding tables, ARP caches and neighbour data into one row
// per endpoint MAC: the switch port it sits on, its VLAN, IP addresses and vendor.
//
// Placing a MAC: in a group of cascaded switches an address is learned on its edge port and on
// every uplink between that port and each other switch. Each MAC is placed at its best
// sighting:
//
//  1. never a port that provably faces another mapped switch (an LLDP/CDP neighbour that is a
//     mapped switch, or a learned address that is a mapped switch's own MAC), when any other
//     sighting exists;
//  2. otherwise the port with the fewest learned MACs: the port nearest the device sees a subset
//     of what the ports upstream of it see;
//  3. heuristic "shared" ports (a bridge/router neighbour such as a hypervisor, or at least
//     UplinkThreshold MACs on a port whose neighbour is not an access point or phone) lose ties.
//
// Entry.UplinkKind says which: "switch" for a port that provably faces a mapped switch (a true
// uplink), "bridge" or "many-macs" for a shared port that is still the right place to report the
// devices behind it.
//
// IP addresses join per MAC and VLAN. A router on a stick, an SVI or a firewall answers on several
// VLANs with one MAC, so an ARP binding goes only on the row of the VLAN it was learned in, when
// that is known (see collect.ARPEntry.VLAN and resolveARPVLANs). A binding that cannot be tied to
// the row's VLAN is listed under other_ips with its VLAN rather than shown as the row's address.
package portmap

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/macaddr"
)

// Entry is one output row: an endpoint MAC on a port, or (with AllPorts) a port with none.
type Entry struct {
	SwitchIndex   int               `json:"switch_index"` // position in the report's switch list
	Switch        string            `json:"switch"`
	SwitchAddr    string            `json:"switch_addr"`
	Port          string            `json:"port"`
	PortAlias     string            `json:"port_alias,omitempty"`
	IfIndex       int               `json:"if_index,omitempty"`
	BridgePort    int               `json:"bridge_port,omitempty"`
	PortStatus    string            `json:"port_status,omitempty"`
	SpeedMbps     uint64            `json:"speed_mbps,omitempty"`
	VLAN          int               `json:"vlan,omitempty"`
	VLANName      string            `json:"vlan_name,omitempty"`
	VLANSource    string            `json:"vlan_source,omitempty"` // fdb, fdb-other-switch (corrected from another switch), port (the port's VLAN membership) or pvid (a guess)
	PortMode      string            `json:"port_mode,omitempty"`   // access, trunk or hybrid (several untagged VLANs), from VLAN membership
	NativeVLAN    int               `json:"native_vlan,omitempty"` // untagged VLAN of a trunk (its PVID when the port sends it untagged)
	TaggedVLANs   string            `json:"tagged_vlans,omitempty"`
	UntaggedVLANs string            `json:"untagged_vlans,omitempty"` // a hybrid port's untagged VLANs
	MemberOf      string            `json:"member_of,omitempty"`      // the aggregate (LAG) this physical port belongs to
	SwitchMAC     string            `json:"switch_mac,omitempty"`     // this MAC is that mapped switch's own (bridge or management) address
	MAC           string            `json:"mac,omitempty"`
	Vendor        string            `json:"vendor,omitempty"`
	IPs           []string          `json:"ips,omitempty"`
	OtherIPs      []string          `json:"other_ips,omitempty"` // this MAC's addresses not tied to this row's VLAN: "ip (VLAN n)" or "ip (VLAN ?)"
	Hostnames     []string          `json:"hostnames,omitempty"`
	MACsOnPort    int               `json:"macs_on_port"`
	Uplink        bool              `json:"uplink,omitempty"`
	UplinkKind    string            `json:"uplink_kind,omitempty"` // switch (faces a mapped switch), bridge, many-macs
	UplinkReason  string            `json:"uplink_reason,omitempty"`
	Neighbor      string            `json:"neighbor,omitempty"`
	Dot1x         string            `json:"dot1x,omitempty"`
	Extra         map[string]string `json:"extra,omitempty"`
	Secondary     bool              `json:"secondary,omitempty"` // not this MAC's best location (AllSightings)
	AlsoSeen      []string          `json:"also_seen,omitempty"` // other ports that learned this MAC

	swIdx int
}

// Options tunes the join.
type Options struct {
	UplinkThreshold int                           // MACs at/above which a port counts as a heuristic uplink; 0 disables
	AllSightings    bool                          // emit every port that learned a MAC, not only the best one
	AllPorts        bool                          // emit physical ports with no endpoint placed on them
	Vendor          func(net.HardwareAddr) string // MAC -> organisation
	MACFormat       string                        // see macaddr.Format
	// LocalMACs maps this machine's interface names and addresses to its MAC on that interface
	// (localarp.OwnMACs), to place local-cache bindings in the VLAN this machine sits in.
	LocalMACs map[string]net.HardwareAddr
}

type portKey struct {
	sw   int
	port int // ifIndex, or -dot1dBasePort when the bridge port has no ifIndex mapping
}

type portState struct {
	key        portKey
	ifx        int
	bridgePort int
	iface      *collect.Interface
	macs       map[string]net.HardwareAddr
	vlans      map[string]map[int]bool // MAC -> VLANs it was learned in on this port
	auth       map[string]bool         // MAC -> its VLAN here came from the FDB (not a PVID guess)
	perVLAN    map[int]map[string]bool // FDB-reported VLAN -> MACs learned in it on this port
	neighbors  []collect.Neighbor
	faces      map[string]bool // mapped switches this port provably faces
	heuristic  string          // why heuristics call this a shared port
	kind       string          // heuristic kind: bridge or many-macs
}

func (p *portState) definitive() bool { return len(p.faces) > 0 }

// sameVLANCount is the number of MACs on p in the VLANs this MAC shares with other, both
// FDB-reported. Trunks with pruned VLANs break a whole-port count (the subset rule holds per
// VLAN), so the comparison is per VLAN whenever both sides know the VLAN; else the port total.
func (p *portState) sameVLANCount(other *portState, mk string) int {
	best := -1
	if p.auth[mk] && other.auth[mk] {
		for v := range p.vlans[mk] {
			if v != 0 && other.vlans[mk][v] {
				if c := len(p.perVLAN[v]); best < 0 || c < best {
					best = c
				}
			}
		}
	}
	if best < 0 {
		return len(p.macs)
	}
	return best
}

// betterFor reports whether a is a better location than b for MAC mk.
func betterFor(mk string, a, b *portState) bool {
	if a.definitive() != b.definitive() {
		return !a.definitive()
	}
	if ca, cb := a.sameVLANCount(b, mk), b.sameVLANCount(a, mk); ca != cb {
		return ca < cb
	}
	if (a.heuristic != "") != (b.heuristic != "") {
		return a.heuristic == ""
	}
	if a.key.sw != b.key.sw {
		return a.key.sw < b.key.sw
	}
	return a.key.port < b.key.port
}

// identity resolves LLDP/CDP neighbours and learned MACs to mapped switches.
type identity struct {
	mac   map[string]int   // bridge base MAC or management-IP MAC -> switch index
	short map[string][]int // NormName(sysName) -> switch indexes
	fqdn  map[string][]int // full lower-case sysName -> switch indexes
}

func newIdentity(switches []*collect.Switch, macByIP map[string]string) identity {
	id := identity{mac: map[string]int{}, short: map[string][]int{}, fqdn: map[string][]int{}}
	for i, s := range switches {
		if s == nil {
			continue
		}
		if s.BaseMAC != nil {
			id.mac[s.BaseMAC.String()] = i
		}
		for _, a := range []string{s.Addr, targetHost(s.Target)} {
			if ip := net.ParseIP(a); ip != nil {
				if m, ok := macByIP[ip.String()]; ok {
					id.mac[m] = i
				}
			}
		}
		if full := fullName(s.SysName); full != "" {
			id.fqdn[full] = append(id.fqdn[full], i)
			id.short[NormName(full)] = append(id.short[NormName(full)], i)
		}
	}
	return id
}

// neighbour returns the mapped switch a neighbour is, or -1. A name counts only when exactly one
// mapped switch carries it (default hostnames like "Switch" are common), and not when the
// neighbour's chassis MAC names a different mapped switch.
func (id identity) neighbour(n collect.Neighbor) int {
	byMAC := -1
	if m, err := macaddr.Parse(n.ChassisID); err == nil {
		if i, ok := id.mac[m.String()]; ok {
			byMAC = i
		}
	}
	byName := -1
	if full := fullName(n.SysName); full != "" {
		if l := id.fqdn[full]; len(l) == 1 {
			byName = l[0]
		} else if l := id.short[NormName(full)]; len(l) == 1 && len(id.fqdn[full]) == 0 {
			byName = l[0]
		}
	}
	switch {
	case byName >= 0 && byMAC >= 0 && byName != byMAC:
		return byMAC
	case byName >= 0:
		return byName
	}
	return byMAC
}

func fullName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '('); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.TrimSuffix(s, ".")
}

// stackInfo answers layering questions for one switch: which ports sit above a port, and which
// bridge port owns a physical port (its LAG, or its Junos logical unit).
type stackInfo struct {
	up     map[int][]int
	lowers map[int]int // ifIndex -> how many interfaces sit directly below it
	bp     map[int]int // ifIndex -> lowest bridge port
}

func newStackInfo(s *collect.Switch, bpOf map[int]int) stackInfo {
	st := stackInfo{up: s.Stack, lowers: map[int]int{}, bp: bpOf}
	for _, highers := range s.Stack {
		for _, h := range highers {
			st.lowers[h]++
		}
	}
	return st
}

// ancestors lists the interfaces above x, nearest first.
func (st stackInfo) ancestors(x int) []int {
	var out []int
	seen := map[int]bool{x: true}
	queue := []int{x}
	for len(queue) > 0 && len(out) < 16 {
		cur := queue[0]
		queue = queue[1:]
		for _, h := range st.up[cur] {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
				queue = append(queue, h)
			}
		}
	}
	return out
}

// owner returns the nearest bridge port above a port that is not itself a bridge port, and
// whether that owner is a logical unit of this port alone (Junos ge-0/0/1.0 over ge-0/0/1) rather
// than an aggregate.
func (st stackInfo) owner(x int) (int, bool) {
	if _, ok := st.bp[x]; ok {
		return 0, false
	}
	for _, a := range st.ancestors(x) {
		if _, ok := st.bp[a]; ok {
			return a, st.lowers[a] <= 1
		}
	}
	return 0, false
}

// Build joins the collected data. switches may contain nil entries (devices that failed); arp
// may come from any mix of routers, switches and the local host.
func Build(switches []*collect.Switch, arp []collect.ARPEntry, opt Options) []Entry {
	if opt.Vendor == nil {
		opt.Vendor = func(net.HardwareAddr) string { return "" }
	}
	macByIP := map[string]string{}
	for _, a := range arp {
		macByIP[a.IP.String()] = a.MAC.String()
	}
	id := newIdentity(switches, macByIP)

	ports := map[portKey]*portState{}
	port := func(si int, s *collect.Switch, ifx, bp int) *portState {
		k := portKey{si, ifx}
		if ifx == 0 {
			k.port = -bp
		}
		ps := ports[k]
		if ps == nil {
			ps = &portState{key: k, ifx: ifx, bridgePort: bp, iface: s.Interfaces[ifx],
				macs: map[string]net.HardwareAddr{}, vlans: map[string]map[int]bool{}, auth: map[string]bool{},
				perVLAN: map[int]map[string]bool{}, faces: map[string]bool{}}
			ports[k] = ps
		}
		if ps.bridgePort == 0 {
			ps.bridgePort = bp
		}
		return ps
	}
	stacks := make([]stackInfo, len(switches))
	sightings := map[string][]portKey{}
	authVLANs := map[string]map[int]bool{} // MAC -> VLANs some switch's FDB reported
	for si, s := range switches {
		if s == nil {
			continue
		}
		bpOf := map[int]int{}
		for bp, ifx := range s.BridgePortIfIndex {
			if cur, ok := bpOf[ifx]; !ok || bp < cur {
				bpOf[ifx] = bp
			}
		}
		stacks[si] = newStackInfo(s, bpOf)
		for _, e := range s.FDB {
			if e.Status == collect.FDBInvalid || e.Status == collect.FDBSelf || !macaddr.Usable(e.MAC) {
				continue
			}
			ifx := e.IfIndex
			if ifx == 0 {
				ifx = s.BridgePortIfIndex[e.BridgePort]
			}
			auth := e.VLAN != 0
			vlan := e.VLAN
			if !auth {
				vlan = guessVLAN(s, e.BridgePort)
			}
			// Membership and PVIDs are keyed by the default instance's bridge ports; a Cisco
			// per-VLAN instance's own number would key another port's row (or nothing).
			bp := e.BridgePort
			if b, ok := bpOf[ifx]; ok && ifx != 0 {
				bp = b
			} else if e.IfIndex != 0 && (len(s.Egress) > 0 || len(s.PVID) > 0) {
				bp = 0
			}
			ps := port(si, s, ifx, bp)
			mk := e.MAC.String()
			if _, ok := ps.macs[mk]; !ok {
				ps.macs[mk] = e.MAC
				sightings[mk] = append(sightings[mk], ps.key)
			}
			if ps.vlans[mk] == nil {
				ps.vlans[mk] = map[int]bool{}
			}
			ps.vlans[mk][vlan] = true
			if auth {
				ps.auth[mk] = true
				if ps.perVLAN[vlan] == nil {
					ps.perVLAN[vlan] = map[string]bool{}
				}
				ps.perVLAN[vlan][mk] = true
				if authVLANs[mk] == nil {
					authVLANs[mk] = map[int]bool{}
				}
				authVLANs[mk][vlan] = true
			}
			if oi, ok := id.mac[mk]; ok && oi != si {
				ps.faces[switches[oi].Name()] = true
			}
		}
		// Neighbours: one heard on a LAG member or a Junos physical port is also credited to the
		// aggregate or logical unit above it, which is where the FDB entries are.
		for _, n := range s.Neighbors {
			if n.IfIndex == 0 {
				continue
			}
			oi := id.neighbour(n)
			targets := []int{n.IfIndex}
			for _, a := range stacks[si].ancestors(n.IfIndex) {
				if _, isBP := bpOf[a]; isBP || ports[portKey{si, a}] != nil {
					targets = append(targets, a)
				}
			}
			for _, t := range targets {
				ps := port(si, s, t, bpOf[t])
				if !hasNeighbor(ps.neighbors, n) {
					ps.neighbors = append(ps.neighbors, n)
				}
				if oi >= 0 && oi != si {
					ps.faces[switches[oi].Name()] = true
				}
			}
		}
	}
	for _, ps := range ports {
		if ps.definitive() {
			continue
		}
		endpoint := false // an AP or phone: the MACs behind it really are on this port
		for _, n := range ps.neighbors {
			if n.Caps.Phone || n.Caps.AP {
				endpoint = true
				continue
			}
			if (n.Caps.Bridge || n.Caps.Router) && ps.heuristic == "" {
				ps.heuristic = fmt.Sprintf("%s neighbour %s is a %s", n.Protocol, firstNonEmpty(n.SysName, n.ChassisID, "?"), capWord(n.Caps))
				ps.kind = "bridge"
			}
		}
		if ps.heuristic == "" && !endpoint && opt.UplinkThreshold > 0 && len(ps.macs) >= opt.UplinkThreshold {
			ps.heuristic, ps.kind = fmt.Sprintf("%d MACs learned", len(ps.macs)), "many-macs"
		}
	}

	bindings := map[string][]collect.ARPEntry{}
	for _, a := range resolveARPVLANs(arp, authVLANs, opt.LocalMACs) {
		bindings[a.MAC.String()] = append(bindings[a.MAC.String()], a)
	}

	var entries []Entry
	emitted := map[portKey]bool{}
	for mk, locs := range sightings {
		// The best location for this MAC (pairwise, VLAN-aware), then the rest in a stable order.
		sort.SliceStable(locs, func(i, j int) bool { return better(ports[locs[i]], ports[locs[j]]) })
		best := 0
		for i := 1; i < len(locs); i++ {
			if betterFor(mk, ports[locs[i]], ports[locs[best]]) {
				best = i
			}
		}
		locs[0], locs[best] = locs[best], locs[0]
		emit := locs[:1]
		if opt.AllSightings {
			emit = locs
		}
		for n, k := range emit {
			ps := ports[k]
			emitted[k] = true
			var also []string
			for _, o := range locs {
				if o != k {
					also = append(also, switches[o.sw].Name()+" "+portLabel(ports[o]))
				}
			}
			mac := ps.macs[mk]
			vlans, source := sortedVLANs(ps.vlans[mk]), "fdb"
			if !ps.auth[mk] {
				switch av := authVLANs[mk]; {
				case len(av) > 0:
					vlans, source = sortedVLANs(av), "fdb-other-switch"
				case accessVLAN(switches[k.sw], ps.bridgePort) != 0:
					source = "port" // an access port: its one VLAN
				default:
					source = "pvid"
				}
			}
			for _, vlan := range vlans {
				e := portRow(switches[k.sw], ps)
				e.VLAN = vlan
				e.VLANName = switches[k.sw].VLANNames[vlan]
				if vlan != 0 {
					e.VLANSource = source
				}
				e.MAC = macaddr.Format(mac, opt.MACFormat)
				e.Vendor = opt.Vendor(mac)
				if oi, ok := id.mac[mk]; ok && oi != k.sw {
					e.SwitchMAC = switches[oi].Name()
				}
				ipVLAN := vlan
				if source == "pvid" {
					ipVLAN = 0 // the row's VLAN is itself a guess: keep every address
				}
				e.IPs, e.OtherIPs = ipsFor(bindings[mk], ipVLAN, vlans)
				e.Secondary = n > 0
				e.AlsoSeen = also
				if o, unit := stacks[k.sw].owner(ps.ifx); o != 0 && !unit {
					e.MemberOf = labelOf(switches[k.sw], o)
				}
				entries = append(entries, e)
			}
		}
	}
	if opt.AllPorts {
		entries = append(entries, emptyPorts(switches, ports, emitted, stacks)...)
	}
	sortEntries(entries)
	return entries
}

// better orders sightings by whole-port evidence (used for listing secondary sightings).
func better(a, b *portState) bool {
	if a.definitive() != b.definitive() {
		return !a.definitive()
	}
	if len(a.macs) != len(b.macs) {
		return len(a.macs) < len(b.macs)
	}
	if (a.heuristic != "") != (b.heuristic != "") {
		return a.heuristic == ""
	}
	if a.key.sw != b.key.sw {
		return a.key.sw < b.key.sw
	}
	return a.key.port < b.key.port
}

func hasNeighbor(list []collect.Neighbor, n collect.Neighbor) bool {
	for _, x := range list {
		if x.Protocol == n.Protocol && x.SysName == n.SysName && x.ChassisID == n.ChassisID && x.PortID == n.PortID {
			return true
		}
	}
	return false
}

func labelOf(s *collect.Switch, ifx int) string {
	if f := s.Interfaces[ifx]; f != nil {
		return f.Label()
	}
	return fmt.Sprintf("ifIndex %d", ifx)
}

// emptyPorts lists physical ports (and unresolved bridge ports) with no endpoint placed on
// them: free ports, and uplinks whose MACs were placed further down. A physical port that is a
// LAG member is listed with member_of; one whose Junos logical unit is the bridge port is
// represented by that unit's row.
func emptyPorts(switches []*collect.Switch, ports map[portKey]*portState, emitted map[portKey]bool, stacks []stackInfo) []Entry {
	var out []Entry
	for si, s := range switches {
		if s == nil {
			continue
		}
		st := stacks[si]
		add := func(ifx int, f *collect.Interface, member int) {
			k := portKey{si, ifx}
			if emitted[k] {
				return
			}
			emitted[k] = true
			ps := ports[k]
			if ps == nil {
				ps = &portState{key: k, ifx: ifx, bridgePort: st.bp[ifx], iface: f, faces: map[string]bool{}}
			}
			e := portRow(s, ps)
			if member != 0 {
				e.MemberOf = labelOf(s, member)
			}
			configuredVLAN(s, &e)
			out = append(out, e)
		}
		for ifx, f := range s.Interfaces {
			owner, unit := st.owner(ifx)
			switch {
			case owner != 0 && unit:
				add(owner, s.Interfaces[owner], 0) // the unit stands for its physical port
			case ports[portKey{si, ifx}] != nil || f.Physical():
				add(ifx, f, owner)
			}
		}
	}
	for k, ps := range ports {
		if k.port < 0 && !emitted[k] && switches[k.sw] != nil {
			emitted[k] = true
			e := portRow(switches[k.sw], ps)
			configuredVLAN(switches[k.sw], &e)
			out = append(out, e)
		}
	}
	return out
}

// portRow fills the per-port columns shared by MAC rows and empty-port rows.
func portRow(s *collect.Switch, ps *portState) Entry {
	e := Entry{
		SwitchIndex: ps.key.sw,
		Switch:      s.Name(),
		SwitchAddr:  s.Target,
		Port:        portLabel(ps),
		IfIndex:     ps.ifx,
		BridgePort:  ps.bridgePort,
		MACsOnPort:  len(ps.macs),
		swIdx:       ps.key.sw,
	}
	if ps.iface != nil {
		e.PortAlias = ps.iface.Alias
		e.PortStatus = ps.iface.Status()
		e.SpeedMbps = ps.iface.SpeedMbps
	}
	var tagged []int
	e.PortMode, e.NativeVLAN, tagged = portMode(s, ps.bridgePort)
	e.TaggedVLANs = vlanRanges(tagged)
	if e.PortMode == "hybrid" {
		e.UntaggedVLANs = vlanRanges(s.Untagged[ps.bridgePort])
	}
	switch {
	case ps.definitive():
		e.Uplink, e.UplinkKind, e.UplinkReason = true, "switch", "faces "+strings.Join(sortedKeys(ps.faces), ", ")
	case ps.heuristic != "":
		e.Uplink, e.UplinkKind, e.UplinkReason = true, ps.kind, ps.heuristic
	}
	var nb []string
	for _, n := range ps.neighbors {
		nb = append(nb, describe(n))
	}
	e.Neighbor = strings.Join(nb, "; ")
	if ps.ifx > 0 {
		if m, ok := s.Dot1x[ps.ifx]; ok {
			e.Dot1x = Dot1xName(m)
		}
		for col, vals := range s.Extra {
			if v, ok := vals[ps.ifx]; ok {
				if e.Extra == nil {
					e.Extra = map[string]string{}
				}
				e.Extra[col] = v
			}
		}
	}
	return e
}

// portMode classifies a bridge port from its VLAN membership: trunk when it carries any VLAN
// tagged (and sends at most one untagged), hybrid when it sends several VLANs untagged, else
// access. For a trunk or hybrid port,
// native is the PVID when the port sends it untagged, else the one VLAN it sends untagged. All
// empty when the agent has no membership table.
func portMode(s *collect.Switch, bp int) (mode string, native int, tagged []int) {
	egress, ok := s.Egress[bp]
	if !ok || bp <= 0 {
		return "", 0, nil
	}
	untagged := map[int]bool{}
	for _, v := range s.Untagged[bp] {
		untagged[v] = true
	}
	for _, v := range egress {
		if !untagged[v] {
			tagged = append(tagged, v)
		}
	}
	switch {
	case len(untagged) > 1:
		mode = "hybrid" // several untagged VLANs (Cisco SMB general mode, Huawei/H3C hybrid), maybe tagged ones too
	case len(tagged) > 0:
		mode = "trunk"
	case len(untagged) == 1:
		return "access", 0, nil // its one VLAN is the row's VLAN
	}
	if pvid := s.PVID[bp]; untagged[pvid] {
		native = pvid
	} else if len(s.Untagged[bp]) == 1 {
		native = s.Untagged[bp][0] // the PVID disagrees with membership (SG350 reports 1 everywhere)
	}
	return mode, native, tagged
}

// accessVLAN is the one VLAN of an access port (one untagged VLAN, nothing tagged), else 0.
func accessVLAN(s *collect.Switch, bp int) int {
	if mode, _, _ := portMode(s, bp); mode == "access" {
		return s.Untagged[bp][0]
	}
	return 0
}

// guessVLAN is the VLAN of a forwarding entry that carries none: an access port's one VLAN,
// else the native VLAN membership gives a trunk or hybrid port, else the PVID. Membership wins
// over the PVID because some agents report every PVID as 1.
func guessVLAN(s *collect.Switch, bp int) int {
	switch mode, native, _ := portMode(s, bp); {
	case mode == "access":
		return s.Untagged[bp][0]
	case native != 0:
		return native
	}
	return s.PVID[bp]
}

// configuredVLAN gives a row with no endpoint the VLAN its port is configured for: an access
// port's one untagged VLAN (vlan_source "port"), or failing membership data the PVID (a guess).
func configuredVLAN(s *collect.Switch, e *Entry) {
	if e.MAC != "" || e.VLAN != 0 || e.BridgePort <= 0 {
		return
	}
	switch {
	case e.PortMode == "access":
		e.VLAN, e.VLANSource = s.Untagged[e.BridgePort][0], "port"
	case e.PortMode == "" && len(s.Egress) == 0 && s.PVID[e.BridgePort] > 0:
		e.VLAN, e.VLANSource = s.PVID[e.BridgePort], "pvid"
	}
	if e.VLAN != 0 {
		e.VLANName = s.VLANNames[e.VLAN]
	}
}

// resolveARPVLANs fills in the VLAN of bindings the FDB can place. A local-cache binding takes
// the one VLAN this machine's own MAC on that interface was learned in ("own-mac"). Otherwise,
// when every address on the binding's interface that the FDB places in exactly one VLAN sits in
// the same VLAN, that VLAN wins ("fdb"); an interface whose addresses disagree says nothing.
// Overruling a VLAN read from an interface name takes at least two such other addresses.
// MACs seen in several VLANs (the router itself) do not vote, and a binding's own MAC never votes
// for it: its FDB VLANs age out one by one, so one VLAN left says little.
func resolveARPVLANs(arp []collect.ARPEntry, authVLANs map[string]map[int]bool, own map[string]net.HardwareAddr) []collect.ARPEntry {
	type group struct {
		source, iface string
		ifx           int
	}
	single := func(m map[int]bool) int {
		if len(m) != 1 {
			return 0
		}
		for v := range m {
			return v
		}
		return 0
	}
	voters := map[group]map[string]int{} // MAC -> its one FDB VLAN
	for _, a := range arp {
		if a.IfIndex <= 0 && a.Iface == "" {
			continue // not tied to an interface: nothing says these bindings share a segment
		}
		g := group{a.Source, a.Iface, a.IfIndex}
		if voters[g] == nil {
			voters[g] = map[string]int{}
		}
		if v := single(authVLANs[a.MAC.String()]); v != 0 {
			voters[g][a.MAC.String()] = v
		}
	}
	type tally struct{ vlan, n int } // the voters' one VLAN (0: none or several), how many voted
	tallies := make(map[group]tally, len(voters))
	for g, vs := range voters {
		all := map[int]bool{}
		for _, v := range vs {
			all[v] = true
		}
		tallies[g] = tally{single(all), len(vs)}
	}
	out := append([]collect.ARPEntry(nil), arp...)
	for i := range out {
		a := &out[i]
		if a.Source == collect.LocalSource {
			if m, ok := own[a.Iface]; ok {
				if v := single(authVLANs[m.String()]); v != 0 {
					a.VLAN, a.VLANBy = v, "own-mac"
					continue
				}
			}
		}
		g := group{a.Source, a.Iface, a.IfIndex}
		t := tallies[g]
		n := t.n
		if _, self := voters[g][a.MAC.String()]; self {
			n-- // its own MAC never votes for it
		}
		if v := t.vlan; v != 0 && v != a.VLAN && n >= 1 && (a.VLAN == 0 || n >= 2) {
			a.VLAN, a.VLANBy = v, "fdb"
		}
	}
	return out
}

// ipsFor splits a MAC's bindings for the row in VLAN vlan (rowVLANs: every VLAN the MAC has a
// row in at this location). A binding in the row's VLAN is the row's address. One whose VLAN is
// unknown is too, unless the MAC sits in several VLANs: then it cannot be tied to this row and is
// listed as other ("ip (VLAN ?)"). One known to be in another VLAN is listed as other
// ("ip (VLAN n)"), unless that VLAN has its own row, where it shows.
func ipsFor(bindings []collect.ARPEntry, vlan int, rowVLANs []int) (ips, other []string) {
	var plain []net.IP
	seen := map[string]bool{}
	hasRow := map[int]bool{}
	for _, v := range rowVLANs {
		hasRow[v] = true
	}
	placed := map[string]bool{} // IPs some source ties to a VLAN: their VLAN-less copies add nothing
	for _, a := range bindings {
		if a.VLAN != 0 {
			placed[a.IP.String()] = true
		}
	}
	for _, a := range bindings {
		if a.VLAN == 0 && placed[a.IP.String()] {
			continue
		}
		switch {
		case vlan == 0 || a.VLAN == vlan || (a.VLAN == 0 && len(rowVLANs) <= 1):
			plain = appendIP(plain, a.IP)
		case a.VLAN == 0:
			if s := a.IP.String() + " (VLAN ?)"; !seen[s] {
				seen[s] = true
				other = append(other, s)
			}
		case !hasRow[a.VLAN]:
			if s := fmt.Sprintf("%s (VLAN %d)", a.IP, a.VLAN); !seen[s] {
				seen[s] = true
				other = append(other, s)
			}
		}
	}
	sortIPs(plain)
	for _, ip := range plain {
		ips = append(ips, ip.String())
	}
	sort.Strings(other)
	return ips, other
}

// vlanRanges renders sorted VLAN IDs compactly: 10,20,30-40.
func vlanRanges(v []int) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		j := i
		for j+1 < len(v) && v[j+1] == v[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		if j > i+1 {
			fmt.Fprintf(&b, "%d-%d", v[i], v[j])
		} else {
			fmt.Fprintf(&b, "%d", v[i])
			if j == i+1 {
				fmt.Fprintf(&b, ",%d", v[j])
			}
		}
		i = j + 1
	}
	return b.String()
}

func portLabel(ps *portState) string {
	switch {
	case ps.iface != nil:
		return ps.iface.Label()
	case ps.ifx > 0:
		return fmt.Sprintf("ifIndex %d", ps.ifx)
	}
	return fmt.Sprintf("bridge port %d", ps.bridgePort)
}

func describe(n collect.Neighbor) string {
	s := n.Protocol + " " + firstNonEmpty(n.SysName, n.ChassisID, "?")
	if p := firstNonEmpty(n.PortID, n.PortDesc); p != "" {
		s += " port " + p
	}
	if n.Platform != "" {
		s += " [" + n.Platform + "]"
	}
	if c := n.Caps.String(); c != "" {
		s += " (" + c + ")"
	}
	return s
}

// Dot1xName names a dot1xAuthAuthControlledPortControl value.
func Dot1xName(v int) string {
	switch v {
	case 1:
		return "force-unauthorized"
	case 2:
		return "auto"
	case 3:
		return "force-authorized"
	}
	return fmt.Sprintf("unknown(%d)", v)
}

func capWord(c collect.Caps) string {
	switch {
	case c.Bridge && c.Router:
		return "bridge/router"
	case c.Router:
		return "router"
	}
	return "bridge"
}

// NormName normalises a system name for matching LLDP/CDP neighbours to mapped switches:
// lower case, a trailing "(serial)" (NX-OS CDP device IDs) removed, and the domain dropped
// unless the name is an IP address.
func NormName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(s, '('); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	if net.ParseIP(s) == nil {
		if i := strings.IndexByte(s, '.'); i > 0 {
			s = s[:i]
		}
	}
	return s
}

func targetHost(t string) string {
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return strings.Trim(t, "[]")
}

func appendIP(ips []net.IP, ip net.IP) []net.IP {
	for _, x := range ips {
		if x.Equal(ip) {
			return ips
		}
	}
	return append(ips, ip)
}

func sortIPs(ips []net.IP) {
	sort.Slice(ips, func(i, j int) bool {
		a4, b4 := ips[i].To4() != nil, ips[j].To4() != nil
		if a4 != b4 {
			return a4
		}
		return string(ips[i].To16()) < string(ips[j].To16())
	})
}

func sortedVLANs(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func sortEntries(e []Entry) {
	sort.SliceStable(e, func(i, j int) bool {
		a, b := e[i], e[j]
		if a.swIdx != b.swIdx {
			return a.swIdx < b.swIdx
		}
		if a.Port != b.Port {
			return NaturalLess(a.Port, b.Port)
		}
		if a.VLAN != b.VLAN {
			return a.VLAN < b.VLAN
		}
		if a.MAC != b.MAC {
			return a.MAC < b.MAC
		}
		return !a.Secondary && b.Secondary
	})
}

// NaturalLess compares strings with digit runs ordered numerically (Gi1/0/2 < Gi1/0/10).
func NaturalLess(a, b string) bool {
	for a != "" && b != "" {
		if isDigit(a[0]) && isDigit(b[0]) {
			na, ra := digits(a)
			nb, rb := digits(b)
			ta, tb := strings.TrimLeft(na, "0"), strings.TrimLeft(nb, "0")
			if len(ta) != len(tb) {
				return len(ta) < len(tb)
			}
			if ta != tb {
				return ta < tb
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func digits(s string) (string, string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}
