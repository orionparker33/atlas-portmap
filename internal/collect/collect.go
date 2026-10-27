package collect

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/macaddr"
	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
)

// collector reads one switch over one session. After the first fatal error (no response,
// authentication, cancellation) it stops issuing requests, so a dead agent costs one timeout
// rather than one per table.
type collector struct {
	sess *snmpc.Session
	sw   *Switch
	err  error
}

// walk reads one table. Rows read before a failure are kept, with a warning that the table is
// incomplete; a fatal error also stops the collector.
func (c *collector) walk(root, what string) []gosnmp.SnmpPDU {
	if c.err != nil {
		return nil
	}
	pdus, err := c.sess.Walk(root)
	if err == nil {
		return pdus
	}
	if snmpc.Fatal(err) {
		c.err = c.sess.Classify(fmt.Errorf("%s: %w", what, err))
		if len(pdus) > 0 {
			c.sw.warnf("%s: incomplete (%d rows read before the agent stopped answering)", what, len(pdus))
		}
		return pdus
	}
	if len(pdus) > 0 {
		c.sw.warnf("%s: incomplete (%d rows): %v", what, len(pdus), err)
	} else {
		c.sw.warnf("%s: %v", what, err)
	}
	return pdus
}

// byIndex keys a column walk by row index.
func byIndex(pdus []gosnmp.SnmpPDU, column string) map[string]gosnmp.SnmpPDU {
	out := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for _, p := range pdus {
		if idx, ok := mib.Suffix(p.Name, column); ok {
			out[idx] = p
		}
	}
	return out
}

// intRows keys rows whose index is a single integer (ifIndex, bridge port, VLAN ID).
func intRows(pdus []gosnmp.SnmpPDU, column string) map[int]gosnmp.SnmpPDU {
	out := map[int]gosnmp.SnmpPDU{}
	for idx, p := range byIndex(pdus, column) {
		if n, err := mib.Int(idx); err == nil {
			out[n] = p
		}
	}
	return out
}

func (c *collector) ints(column, what string) map[int]int64 {
	out := map[int]int64{}
	for k, p := range intRows(c.walk(column, what), column) {
		if v, ok := mib.IntValue(p); ok {
			out[k] = v
		}
	}
	return out
}

func (c *collector) texts(column, what string) map[int]string {
	out := map[int]string{}
	for k, p := range intRows(c.walk(column, what), column) {
		out[k] = mib.Text(p)
	}
	return out
}

// CollectSwitch reads everything atlas-portmap needs from one switch. A non-nil Switch with a
// non-nil error is partial data: the agent stopped answering part-way.
func CollectSwitch(ctx context.Context, target string, cfg snmpc.Config, opt Options) (*Switch, error) {
	sess, err := snmpc.Dial(ctx, target, cfg, 0)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	sw := newSwitch(target)
	c := &collector{sess: sess, sw: sw}

	// The system group doubles as the reachability and credentials check. sysName goes first,
	// once before any retries (FirstContact), so wrong credentials cost one attempt. A refusal
	// (authorizationError, noAccess) covers the whole request, so it fails the switch; any
	// other error-status only means sysName is missing.
	var p gosnmp.SnmpPDU
	var ok bool
	err = sess.FirstContact(func() (err error) {
		p, ok, err = sess.Get(mib.SysName)
		return err
	})
	switch {
	case snmpc.IsDenied(err):
		return nil, sess.Classify(err)
	case snmpc.IsAgentError(err):
		sw.warnf("sysName: %v", err)
	case err != nil:
		return nil, sess.Classify(err)
	}
	if ok {
		sw.SysName = mib.Text(p)
	}
	// Optional scalars: any error (an error-status, or an agent silent on one subtree) just
	// leaves the field empty; the table walks decide whether the agent still answers.
	if p, ok, _ := sess.Get(mib.SysDescr); ok {
		sw.SysDescr = mib.Text(p)
	}
	if p, ok, _ := sess.Get(mib.SysObjectID); ok {
		sw.SysObjectID = mib.Text(p)
		sw.Enterprise = mib.Enterprise(sw.SysObjectID)
	}
	if p, ok, _ := sess.Get(mib.Dot1dBaseBridgeAddress); ok {
		if m, ok := mib.MACValue(p); ok && macaddr.Usable(m) {
			sw.BaseMAC = m
		}
	}

	sw.Addr = sess.RemoteIP()
	c.interfaces()
	c.stack()
	c.bridgePorts()
	c.qBridge(opt)
	if len(sw.FDB) == 0 {
		c.bridgeFDB()
	}
	c.ciscoPerVLAN(ctx, cfg, opt)
	if opt.LLDP {
		c.lldp()
	}
	if opt.CDP {
		c.cdp()
	}
	if opt.Dot1x {
		c.dot1x()
	}
	if sw.Enterprise == mib.EnterpriseCisco {
		c.ciscoPortNames()
	}
	for _, col := range opt.Columns {
		c.extra(col)
	}
	if sw.FDBSource == "" && c.err == nil {
		sw.warnf("no forwarding database readable (BRIDGE-MIB and Q-BRIDGE-MIB empty; check the SNMP view)")
	}
	if sw.FDBSource == "bridge" && len(sw.PVID) > 0 {
		sw.warnf("BRIDGE-MIB forwarding table has no VLANs: VLANs come from port PVIDs, so tagged traffic shows the native VLAN (vlan_source=pvid)")
	}
	for _, n := range sess.Notes {
		sw.warnf("%s", n)
	}
	return sw, c.err
}

// stack records interface layering: IF-MIB ifStackTable (LAG over members, Junos logical units
// over physical ports) and IEEE8023-LAG-MIB member-to-aggregator attachment. Neighbours heard
// on a physical port are then credited to the aggregate or unit that holds the FDB entries.
func (c *collector) stack() {
	sw := c.sw
	add := func(lower, higher int) {
		if lower <= 0 || higher <= 0 || lower == higher {
			return
		}
		for _, h := range sw.Stack[lower] {
			if h == higher {
				return
			}
		}
		sw.Stack[lower] = append(sw.Stack[lower], higher)
	}
	for idx := range byIndex(c.walk(mib.IfStackStatus, "ifStackStatus"), mib.IfStackStatus) {
		if v, err := mib.Ints(idx); err == nil && len(v) == 2 {
			add(int(v[1]), int(v[0]))
		}
	}
	for member, agg := range c.ints(mib.Dot3adAggPortAttachedAggID, "dot3adAggPortAttachedAggID") {
		add(member, int(agg))
	}
}

// juniperVLANs maps Junos internal VLAN indexes (and FDB IDs) to 802.1Q tags.
type juniperVLANs struct {
	intToTag map[int]int
	fidToTag map[int]int
	tags     map[int]bool
}

func (c *collector) juniperVLANs() *juniperVLANs {
	if c.sw.Enterprise != mib.EnterpriseJuniper {
		return nil
	}
	j := &juniperVLANs{intToTag: map[int]int{}, fidToTag: map[int]int{}, tags: map[int]bool{}}
	fids := c.ints(mib.JnxL2aldVlanFdbID, "jnxL2aldVlanFdbId")
	for idx, tag := range c.ints(mib.JnxL2aldVlanTag, "jnxL2aldVlanTag") {
		if tag >= 1 && tag <= 4094 {
			j.intToTag[idx], j.tags[int(tag)] = int(tag), true
			if fid, ok := fids[idx]; ok && fid > 0 {
				j.fidToTag[int(fid)] = int(tag)
			}
		}
	}
	if len(j.intToTag) == 0 {
		for idx, tag := range c.ints(mib.JnxExVlanTag, "jnxExVlanTag") {
			if tag >= 1 && tag <= 4094 {
				j.intToTag[idx], j.tags[int(tag)] = int(tag), true
			}
		}
	}
	if len(j.intToTag) == 0 {
		return nil
	}
	return j
}

// index turns a Q-BRIDGE VLAN index or PVID into its 802.1Q tag: Junos ELS numbers Q-BRIDGE
// VLANs by an internal index, so the internal-index map comes first.
func (j *juniperVLANs) index(v int) int {
	if j != nil {
		if t, ok := j.intToTag[v]; ok {
			return t
		}
	}
	return v
}

// tag turns a value that may already be an 802.1Q tag (an FDB ID used as the VLAN) into one;
// a Junos internal index passes through its map.
func (j *juniperVLANs) tag(v int) int {
	if j == nil || j.tags[v] {
		return v
	}
	if t, ok := j.intToTag[v]; ok {
		return t
	}
	return v
}

func (c *collector) interfaces() {
	sw := c.sw
	get := func(i int) *Interface {
		if f := sw.Interfaces[i]; f != nil {
			return f
		}
		f := &Interface{IfIndex: i}
		sw.Interfaces[i] = f
		return f
	}
	for i, v := range c.texts(mib.IfDescr, "ifDescr") {
		get(i).Descr = v
	}
	for i, v := range c.texts(mib.IfName, "ifName") {
		get(i).Name = v
	}
	for i, v := range c.texts(mib.IfAlias, "ifAlias") {
		get(i).Alias = v
	}
	for i, v := range c.ints(mib.IfType, "ifType") {
		get(i).Type = int(v)
	}
	for i, v := range c.ints(mib.IfAdminStatus, "ifAdminStatus") {
		get(i).Admin = int(v)
	}
	for i, v := range c.ints(mib.IfOperStatus, "ifOperStatus") {
		get(i).Oper = int(v)
	}
	for i, v := range c.ints(mib.IfHighSpeed, "ifHighSpeed") {
		if v > 0 {
			get(i).SpeedMbps = uint64(v)
		}
	}
	if len(sw.Interfaces) == 0 && c.err == nil {
		sw.warnf("IF-MIB returned no interfaces (check the SNMP view)")
	}
}

func (c *collector) bridgePorts() {
	for bp, ifx := range c.ints(mib.Dot1dBasePortIfIndex, "dot1dBasePortIfIndex") {
		if ifx > 0 {
			c.sw.BridgePortIfIndex[bp] = int(ifx)
		}
	}
}

// qBridge reads the VLAN-aware FDB plus PVIDs and VLAN names.
func (c *collector) qBridge(opt Options) {
	sw := c.sw
	jv := c.juniperVLANs()
	// FDB ID -> VLANs. Independent VLAN learning gives each VLAN its own FID; under shared
	// learning several VLANs share one FID and the FDB alone cannot say which VLAN a MAC is in.
	fidVLANs := map[int][]int{}
	for idx, p := range byIndex(c.walk(mib.Dot1qVlanFdbId, "dot1qVlanFdbId"), mib.Dot1qVlanFdbId) {
		v, err := mib.Ints(idx)
		fid, ok := mib.IntValue(p)
		if err != nil || len(v) != 2 || !ok {
			continue
		}
		fidVLANs[int(fid)] = append(fidVLANs[int(fid)], jv.index(int(v[1])))
	}
	for bp, pvid := range c.ints(mib.Dot1qPvid, "dot1qPvid") {
		if pvid > 0 {
			sw.PVID[bp] = jv.index(int(pvid))
		}
	}
	if egress, eRows := c.portLists(mib.Dot1qVlanCurrentEgressPorts, "dot1qVlanCurrentEgressPorts", jv); len(egress) > 0 {
		// Both columns describe the same rows: a VLAN read in one but not the other would make its
		// untagged members look tagged, so membership is all or nothing.
		untagged, uRows := c.portLists(mib.Dot1qVlanCurrentUntaggedPorts, "dot1qVlanCurrentUntaggedPorts", jv)
		if !sameKeys(eRows, uRows) {
			sw.warnf("VLAN membership incomplete (dot1qVlanCurrentTable egress for %d VLANs, untagged for %d): port modes not reported", len(eRows), len(uRows))
		} else {
			sw.Egress, sw.Untagged = egress, untagged
		}
		// Some firmware (Cisco SG350 2.5) reports PVID 1 on every port: say so, membership wins.
		// An access port's PVID is its one untagged VLAN, so any mismatch means the PVIDs are off.
		access, wrong := 0, 0
		for bp, un := range sw.Untagged {
			if len(un) == 1 && len(sw.Egress[bp]) == 1 && sw.PVID[bp] > 0 {
				access++
				if sw.PVID[bp] != un[0] {
					wrong++
				}
			}
		}
		if wrong > 0 {
			sw.warnf("dot1qPvid disagrees with VLAN membership on %d of %d access ports; VLANs come from membership", wrong, access)
		}
	}
	if opt.VLANNames {
		for vid, name := range c.texts(mib.Dot1qVlanStaticName, "dot1qVlanStaticName") {
			if name != "" {
				sw.VLANNames[jv.index(vid)] = name
			}
		}
	}
	ports := byIndex(c.walk(mib.Dot1qTpFdbPort, "dot1qTpFdbPort"), mib.Dot1qTpFdbPort)
	if len(ports) == 0 {
		return
	}
	status := byIndex(c.walk(mib.Dot1qTpFdbStatus, "dot1qTpFdbStatus"), mib.Dot1qTpFdbStatus)
	shared := map[int]bool{}
	notVLAN := 0
	for idx, p := range ports {
		v, err := mib.Ints(idx)
		if err != nil || len(v) != 7 {
			continue
		}
		mac, err := mib.MAC(v[1:])
		bp, ok := mib.IntValue(p)
		if err != nil || !ok || bp <= 0 { // port 0: address known, but not on a port
			continue
		}
		fid := int(v[0])
		vlan := 0
		switch vl := fidVLANs[fid]; {
		case jv != nil && jv.fidToTag[fid] > 0:
			vlan = jv.fidToTag[fid]
		case len(vl) == 1:
			vlan = vl[0]
		case len(vl) > 1:
			shared[fid] = true
		case fid >= 1 && fid <= 4094:
			vlan = jv.tag(fid) // no dot1qVlanCurrentTable: most agents use FID == VLAN ID
		default:
			notVLAN++ // not a VLAN ID; resolve from the PVID
		}
		e := FDBEntry{MAC: mac, BridgePort: int(bp), VLAN: vlan}
		if s, ok := status[idx]; ok {
			if n, ok := mib.IntValue(s); ok {
				e.Status = int(n)
			}
		}
		sw.FDB = append(sw.FDB, e)
	}
	if notVLAN > 0 {
		sw.warnf("%d forwarding entries carry FDB IDs that are not VLAN IDs and no FDB-to-VLAN table; their VLAN comes from the port PVID", notVLAN)
	}
	for _, fid := range sortedInts(shared) {
		vl := append([]int(nil), fidVLANs[fid]...)
		sort.Ints(vl)
		sw.warnf("shared VLAN learning: FDB %d spans VLANs %s; VLAN taken from the port PVID", fid, joinInts(vl))
	}
	sw.FDBSource = "q-bridge"
}

// portLists reads a dot1qVlanCurrentTable PortList column into bridge port -> VLANs. The table
// is the agent's live view (static and dynamic membership); its rows are per time mark, and the
// marks are merged.
func (c *collector) portLists(column, what string, jv *juniperVLANs) (map[int][]int, map[int]bool) {
	sets, rows := map[int]map[int]bool{}, map[int]bool{}
	for idx, p := range byIndex(c.walk(column, what), column) {
		v, err := mib.Ints(idx)
		b, ok := mib.Bytes(p)
		if err != nil || len(v) != 2 || !ok {
			continue
		}
		vid := jv.index(int(v[1]))
		if vid < 1 || vid > 4094 {
			continue
		}
		rows[vid] = true
		for _, bp := range mib.PortList(b) {
			if sets[bp] == nil {
				sets[bp] = map[int]bool{}
			}
			sets[bp][vid] = true
		}
	}
	out := make(map[int][]int, len(sets))
	for bp, s := range sets {
		out[bp] = sortedInts(s)
	}
	return out, rows
}

func sameKeys(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func (c *collector) bridgeFDB() {
	ports := byIndex(c.walk(mib.Dot1dTpFdbPort, "dot1dTpFdbPort"), mib.Dot1dTpFdbPort)
	if len(ports) == 0 {
		return
	}
	status := byIndex(c.walk(mib.Dot1dTpFdbStatus, "dot1dTpFdbStatus"), mib.Dot1dTpFdbStatus)
	c.sw.FDB = bridgeEntries(ports, status, nil, 0)
	c.sw.FDBSource = "bridge"
}

// bridgeEntries turns dot1dTpFdbTable rows into FDB entries. bpIf, when non-nil, resolves
// bridge ports at once: each per-VLAN bridge instance numbers its own ports.
func bridgeEntries(ports, status map[string]gosnmp.SnmpPDU, bpIf map[int]int, vlan int) []FDBEntry {
	var out []FDBEntry
	for idx, p := range ports {
		v, err := mib.Ints(idx)
		if err != nil || len(v) != 6 {
			continue
		}
		mac, err := mib.MAC(v)
		bp, ok := mib.IntValue(p)
		if err != nil || !ok || bp <= 0 {
			continue
		}
		e := FDBEntry{MAC: mac, BridgePort: int(bp), VLAN: vlan}
		if bpIf != nil {
			e.IfIndex = bpIf[int(bp)]
		}
		if s, ok := status[idx]; ok {
			if n, ok := mib.IntValue(s); ok {
				e.Status = int(n)
			}
		}
		out = append(out, e)
	}
	return out
}

// ciscoPerVLAN reads Cisco's per-VLAN BRIDGE-MIB instances. Cisco IOS answers BRIDGE-MIB for
// one VLAN per request and selects it with community "<community>@<vlan>" (v1/v2c) or context
// "vlan-<vlan>" (v3); without this only the default VLAN's addresses are visible.
func (c *collector) ciscoPerVLAN(ctx context.Context, cfg snmpc.Config, opt Options) {
	sw := c.sw
	if c.err != nil {
		return
	}
	switch opt.CiscoPerVLAN {
	case "off":
		return
	case "on":
	default:
		if sw.Enterprise != mib.EnterpriseCisco || sw.FDBSource == "q-bridge" {
			return
		}
	}
	vlans := opt.VLANs
	if len(vlans) == 0 {
		vlans = c.vtpVLANs()
	}
	if len(vlans) == 0 {
		if c.err == nil {
			if opt.CiscoPerVLAN == "on" {
				sw.warnf("per-VLAN collection: no VLAN list (CISCO-VTP-MIB empty); pass -vlans")
			} else {
				sw.warnf("Cisco switch without readable CISCO-VTP-MIB: only the default BRIDGE-MIB instance (VLAN 1 on IOS) was read; pass -vlans to read the other VLANs")
			}
		}
		return
	}
	fdb, res := perVLAN(ctx, sw.Target, cfg, vlans)
	if len(res.skipped) > 0 {
		sw.warnf("per-VLAN instances not answering: stopped after %d timeouts, %d VLANs not tried (is community@vlan or v3 context vlan-N permitted?)", breakerAfter, len(res.skipped))
	}
	if len(res.failed) > 0 {
		sw.warnf("per-VLAN BRIDGE-MIB not readable for VLAN %s (community@vlan or v3 context vlan-N not permitted, or no such instance)", joinInts(res.failed))
	}
	if len(fdb) == 0 && len(res.empty) > 0 && len(sw.FDB) > 0 && len(vlans) > 1 {
		sw.warnf("per-VLAN BRIDGE-MIB instances returned nothing (VLAN %s): the SNMP view or v3 group probably excludes the vlan- contexts, so only the default instance (VLAN 1 on IOS) was mapped", joinInts(res.empty))
	}
	if len(fdb) > 0 {
		// Keep default-instance addresses that no per-VLAN walk saw (a VLAN whose instance
		// failed, or one missing from the VLAN list), so a partial failure loses nothing.
		seen := map[string]bool{}
		for _, e := range fdb {
			seen[e.MAC.String()] = true
		}
		for _, e := range sw.FDB {
			if !seen[e.MAC.String()] {
				fdb = append(fdb, e)
			}
		}
		sw.FDB, sw.FDBSource = fdb, "cisco-per-vlan"
	}
}

// vtpVLANs lists operational Ethernet VLANs from CISCO-VTP-MIB, without the FDDI/Token Ring
// defaults 1002-1005.
func (c *collector) vtpVLANs() []int {
	states := byIndex(c.walk(mib.VtpVlanState, "vtpVlanState"), mib.VtpVlanState)
	if len(states) == 0 {
		return nil
	}
	types := byIndex(c.walk(mib.VtpVlanType, "vtpVlanType"), mib.VtpVlanType)
	seen := map[int]bool{}
	for idx, p := range states {
		v, err := mib.Ints(idx)
		if err != nil || len(v) != 2 {
			continue
		}
		vid := int(v[1])
		if st, ok := mib.IntValue(p); !ok || st != 1 {
			continue
		}
		if t, ok := types[idx]; ok {
			if n, ok := mib.IntValue(t); ok && n != 1 {
				continue
			}
		}
		if vid < 1 || vid > 4094 || (vid >= 1002 && vid <= 1005) {
			continue
		}
		seen[vid] = true
	}
	return sortedInts(seen)
}

// breakerAfter is how many per-VLAN instances may time out, with none answering, before the
// rest are skipped: an agent that does not permit community@vlan answers none of them.
const breakerAfter = 4

type perVLANResult struct {
	failed, empty, skipped []int
}

// vlanRead is the outcome of reading one VLAN's bridge instance.
type vlanRead struct {
	fdb   []FDBEntry
	state int
}

const (
	vlanFailed = iota
	vlanOK
	vlanEmpty
	vlanSkipped
)

// perVLAN walks each VLAN's BRIDGE-MIB instance. A VLAN without an instance makes the agent
// drop the request, so each VLAN gets a single attempt; four run at a time. An instance that
// answers but holds no bridge ports and no addresses counts as empty, not as read. After
// breakerAfter timeouts with no instance answering, the remaining VLANs are skipped.
func perVLAN(ctx context.Context, target string, cfg snmpc.Config, vlans []int) ([]FDBEntry, perVLANResult) {
	cfg.Retries = 0
	results := make([]vlanRead, len(vlans))
	var mu sync.Mutex
	answered, timeouts, tripped := 0, 0, false
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, vid := range vlans {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			stop := tripped
			mu.Unlock()
			if stop || ctx.Err() != nil {
				results[i].state = vlanSkipped
				return
			}
			r, timedOut := readVLAN(ctx, target, cfg, vid)
			results[i] = r
			mu.Lock()
			defer mu.Unlock()
			switch {
			case r.state == vlanOK || r.state == vlanEmpty:
				answered++
			case timedOut && answered == 0:
				if timeouts++; timeouts >= breakerAfter {
					tripped = true
				}
			}
		}()
	}
	wg.Wait()
	var fdb []FDBEntry
	var res perVLANResult
	for i, r := range results {
		switch r.state {
		case vlanOK:
			fdb = append(fdb, r.fdb...)
		case vlanEmpty:
			res.empty = append(res.empty, vlans[i])
		case vlanSkipped:
			res.skipped = append(res.skipped, vlans[i])
		default:
			res.failed = append(res.failed, vlans[i])
		}
	}
	return fdb, res
}

// readVLAN reads one VLAN instance; the bool reports a timeout (for the circuit breaker).
func readVLAN(ctx context.Context, target string, cfg snmpc.Config, vid int) (vlanRead, bool) {
	s, err := snmpc.Dial(ctx, target, cfg, vid)
	if err != nil {
		return vlanRead{state: vlanFailed}, false
	}
	defer s.Close()
	bp, err := s.Walk(mib.Dot1dBasePortIfIndex)
	if err != nil && len(bp) == 0 {
		return vlanRead{state: vlanFailed}, snmpc.IsTimeout(err)
	}
	bpIf := map[int]int{}
	for port, p := range intRows(bp, mib.Dot1dBasePortIfIndex) {
		if n, ok := mib.IntValue(p); ok && n > 0 {
			bpIf[port] = int(n)
		}
	}
	ports, err := s.Walk(mib.Dot1dTpFdbPort)
	if err != nil && len(ports) == 0 && len(bpIf) == 0 {
		return vlanRead{state: vlanFailed}, snmpc.IsTimeout(err)
	}
	status, _ := s.Walk(mib.Dot1dTpFdbStatus)
	entries := bridgeEntries(byIndex(ports, mib.Dot1dTpFdbPort), byIndex(status, mib.Dot1dTpFdbStatus), bpIf, vid)
	if len(bpIf) == 0 && len(entries) == 0 {
		return vlanRead{state: vlanEmpty}, false
	}
	return vlanRead{state: vlanOK, fdb: entries}, false
}

func (c *collector) dot1x() {
	for ifx, v := range c.ints(mib.Dot1xAuthAuthControlledPortControl, "dot1xAuthAuthControlledPortControl") {
		c.sw.Dot1x[ifx] = int(v)
	}
}

// ciscoPortNames fills empty ifAlias values from CISCO-STACK-MIB portName (CatOS, older IOS).
func (c *collector) ciscoPortNames() {
	names := byIndex(c.walk(mib.CiscoPortName, "portName"), mib.CiscoPortName)
	if len(names) == 0 {
		return
	}
	ifx := byIndex(c.walk(mib.CiscoPortIfIndex, "portIfIndex"), mib.CiscoPortIfIndex)
	for idx, p := range names {
		name := mib.Text(p)
		ip, ok := ifx[idx]
		if name == "" || !ok {
			continue
		}
		if n, ok := mib.IntValue(ip); ok {
			if f := c.sw.Interfaces[int(n)]; f != nil && f.Alias == "" {
				f.Alias = name
			}
		}
	}
}

func (c *collector) extra(col Column) {
	pdus := c.walk(col.OID, col.Name)
	vals := map[int]string{}
	for ifx, p := range intRows(pdus, col.OID) {
		vals[ifx] = mib.Text(p)
	}
	switch {
	case len(vals) == 0 && len(pdus) > 0:
		idx, _ := mib.Suffix(pdus[0].Name, col.OID)
		c.sw.warnf("column %s (%s): rows are indexed by %s, not by ifIndex; -column needs a table indexed by ifIndex", col.Name, col.OID, idx)
	case len(vals) == 0 && c.err == nil:
		c.sw.warnf("column %s (%s): no rows", col.Name, col.OID)
	}
	c.sw.Extra[col.Name] = vals
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ",")
}
