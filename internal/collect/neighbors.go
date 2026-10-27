package collect

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/orionparker33/atlas-portmap/internal/macaddr"
	"github.com/orionparker33/atlas-portmap/internal/mib"
)

func (c *collector) lldp() {
	sw := c.sw
	locSub := c.ints(mib.LldpLocPortIdSubtype, "lldpLocPortIdSubtype")
	locID := map[int][]byte{}
	for n, p := range intRows(c.walk(mib.LldpLocPortId, "lldpLocPortId"), mib.LldpLocPortId) {
		if b, ok := mib.Bytes(p); ok {
			locID[n] = b
		}
	}
	locDesc := c.texts(mib.LldpLocPortDesc, "lldpLocPortDesc")

	type remote struct {
		localPort    int
		chSub, ptSub int64
		ch, pt, caps []byte
		desc, name   string
	}
	rems := map[string]*remote{}
	get := func(idx string) *remote {
		if r := rems[idx]; r != nil {
			return r
		}
		v, err := mib.Ints(idx)
		if err != nil || len(v) != 3 {
			return nil
		}
		r := &remote{localPort: int(v[1])}
		rems[idx] = r
		return r
	}
	each := func(column, what string, set func(*remote, []byte, string, int64)) {
		for idx, p := range byIndex(c.walk(column, what), column) {
			if r := get(idx); r != nil {
				b, _ := mib.Bytes(p)
				n, _ := mib.IntValue(p)
				set(r, b, mib.Text(p), n)
			}
		}
	}
	each(mib.LldpRemChassisIdSubtype, "lldpRemChassisIdSubtype", func(r *remote, _ []byte, _ string, n int64) { r.chSub = n })
	each(mib.LldpRemChassisId, "lldpRemChassisId", func(r *remote, b []byte, _ string, _ int64) { r.ch = b })
	each(mib.LldpRemPortIdSubtype, "lldpRemPortIdSubtype", func(r *remote, _ []byte, _ string, n int64) { r.ptSub = n })
	each(mib.LldpRemPortId, "lldpRemPortId", func(r *remote, b []byte, _ string, _ int64) { r.pt = b })
	each(mib.LldpRemPortDesc, "lldpRemPortDesc", func(r *remote, _ []byte, t string, _ int64) { r.desc = t })
	each(mib.LldpRemSysName, "lldpRemSysName", func(r *remote, _ []byte, t string, _ int64) { r.name = t })
	each(mib.LldpRemSysCapEnabled, "lldpRemSysCapEnabled", func(r *remote, b []byte, _ string, _ int64) { r.caps = b })

	sw.LLDPSeen = len(locSub) > 0 || len(locID) > 0 || len(rems) > 0
	if !sw.LLDPSeen {
		if c.err == nil {
			sw.warnf("LLDP not exposed (LLDP-MIB empty): enable LLDP on this switch and its neighbours for reliable uplink detection")
		}
		return
	}
	keys := make([]string, 0, len(rems))
	for k := range rems {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r := rems[k]
		ifx, how := ResolveLLDPPort(sw, r.localPort, int(locSub[r.localPort]), locID[r.localPort], locDesc[r.localPort])
		sw.Neighbors = append(sw.Neighbors, Neighbor{
			IfIndex:    ifx,
			LocalPort:  r.localPort,
			Protocol:   "lldp",
			SysName:    r.name,
			ChassisID:  lldpChassisID(int(r.chSub), r.ch),
			PortID:     lldpPortID(int(r.ptSub), r.pt),
			PortDesc:   r.desc,
			Caps:       LLDPCaps(r.caps),
			ResolvedBy: how,
		})
	}
}

// ResolveLLDPPort maps an lldpRemLocalPortNum to an ifIndex. 802.1AB says lldpPortNumber is the
// dot1dBasePort on a bridge, but agents differ (many use the ifIndex), so the local port's own
// ID and description are matched against IF-MIB first; the numeric fallbacks come last.
func ResolveLLDPPort(sw *Switch, portNum, subtype int, id []byte, desc string) (int, string) {
	idText := ""
	if subtype != 3 { // macAddress
		idText = mib.OctetText(id)
	}
	if subtype != 3 && subtype != 4 { // not macAddress / networkAddress: the ID is a name
		if ifx := matchInterface(sw, idText); ifx > 0 {
			return ifx, "lldpLocPortId"
		}
	}
	if ifx := matchInterface(sw, desc); ifx > 0 {
		return ifx, "lldpLocPortDesc"
	}
	if subtype == 7 { // local: commonly the ifIndex
		if n, err := strconv.Atoi(strings.TrimSpace(idText)); err == nil && sw.Interfaces[n] != nil {
			return n, "lldpLocPortId(local)=ifIndex"
		}
	}
	if ifx, ok := sw.BridgePortIfIndex[portNum]; ok {
		return ifx, "lldpPortNumber=dot1dBasePort"
	}
	if sw.Interfaces[portNum] != nil {
		return portNum, "lldpPortNumber=ifIndex"
	}
	return 0, "unresolved"
}

// matchInterface finds the one interface whose ifName, then ifDescr, then ifAlias equals name,
// exactly (case-insensitive) or after abbreviation (GigabitEthernet1/0/1 = Gi1/0/1).
func matchInterface(sw *Switch, name string) int {
	name = strings.TrimSpace(name)
	if name == "" {
		return 0
	}
	fields := []func(*Interface) string{
		func(f *Interface) string { return f.Name },
		func(f *Interface) string { return f.Descr },
		func(f *Interface) string { return f.Alias },
	}
	for _, field := range fields {
		for _, norm := range []func(string) string{strings.ToLower, IfKey} {
			want, hit, n := norm(name), 0, 0
			for idx, f := range sw.Interfaces {
				if v := field(f); v != "" && norm(v) == want {
					hit, n = idx, n+1
				}
			}
			if n == 1 {
				return hit
			}
		}
	}
	return 0
}

var ifPrefixes = []struct{ long, short string }{
	{"hundredgigabitethernet", "hu"}, {"hundredgige", "hu"},
	{"fortygigabitethernet", "fo"}, {"fortygige", "fo"},
	{"twentyfivegigabitethernet", "twe"}, {"twentyfivegige", "twe"},
	{"tengigabitethernet", "te"}, {"tengige", "te"},
	{"fivegigabitethernet", "fi"}, {"twogigabitethernet", "tw"},
	{"gigabitethernet", "gi"}, {"fastethernet", "fa"},
	{"port-channel", "po"}, {"portchannel", "po"},
	{"ethernet", "eth"},
}

// IfKey normalises an interface name for comparison: lower case, no spaces, long Cisco-style
// prefixes abbreviated.
func IfKey(s string) string {
	k := strings.ToLower(strings.Join(strings.Fields(s), ""))
	for _, p := range ifPrefixes {
		if strings.HasPrefix(k, p.long) {
			return p.short + k[len(p.long):]
		}
	}
	return k
}

// lldpChassisID renders a chassis ID by LldpChassisIdSubtype (4 macAddress, 5 networkAddress).
func lldpChassisID(subtype int, b []byte) string {
	switch subtype {
	case 4:
		if len(b) == 6 {
			return macaddr.Format(b, "colon")
		}
	case 5:
		return netAddr(b)
	}
	return mib.OctetText(b)
}

// lldpPortID renders a port ID by LldpPortIdSubtype (3 macAddress, 4 networkAddress).
func lldpPortID(subtype int, b []byte) string {
	switch subtype {
	case 3:
		if len(b) == 6 {
			return macaddr.Format(b, "colon")
		}
	case 4:
		return netAddr(b)
	}
	return mib.OctetText(b)
}

// netAddr decodes an LLDP network address: an IANA address-family octet, then the address.
func netAddr(b []byte) string {
	switch {
	case len(b) == 5 && b[0] == 1:
		return net.IP(b[1:]).String()
	case len(b) == 17 && b[0] == 2:
		return net.IP(b[1:]).String()
	}
	return mib.OctetText(b)
}

// LLDPCaps decodes LldpSystemCapabilitiesMap BITS. Bit 0 is the most significant bit of the
// first octet: other, repeater, bridge, wlanAccessPoint, router, telephone, docsisCableDevice,
// stationOnly; LLDP-V2 continues with cVLAN and sVLAN components (bits 8, 9).
func LLDPCaps(b []byte) Caps {
	bit := func(n int) bool { return n/8 < len(b) && b[n/8]&(0x80>>(n%8)) != 0 }
	return Caps{
		Other:    bit(0),
		Repeater: bit(1),
		Bridge:   bit(2) || bit(8) || bit(9),
		AP:       bit(3),
		Router:   bit(4),
		Phone:    bit(5),
		Station:  bit(7),
	}
}

func (c *collector) cdp() {
	sw := c.sw
	ids := byIndex(c.walk(mib.CdpCacheDeviceId, "cdpCacheDeviceId"), mib.CdpCacheDeviceId)
	if len(ids) == 0 {
		return
	}
	ports := byIndex(c.walk(mib.CdpCacheDevicePort, "cdpCacheDevicePort"), mib.CdpCacheDevicePort)
	plats := byIndex(c.walk(mib.CdpCachePlatform, "cdpCachePlatform"), mib.CdpCachePlatform)
	caps := byIndex(c.walk(mib.CdpCacheCapabilities, "cdpCacheCapabilities"), mib.CdpCacheCapabilities)
	keys := make([]string, 0, len(ids))
	for k := range ids {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, idx := range keys {
		v, err := mib.Ints(idx)
		if err != nil || len(v) != 2 {
			continue
		}
		ifx := int(v[0])
		n := Neighbor{IfIndex: ifx, LocalPort: ifx, Protocol: "cdp", SysName: mib.Text(ids[idx]), ResolvedBy: "cdpCacheIfIndex"}
		if p, ok := ports[idx]; ok {
			n.PortID = mib.Text(p)
		}
		if p, ok := plats[idx]; ok {
			n.Platform = mib.Text(p)
		}
		var bits []byte
		if p, ok := caps[idx]; ok {
			bits, _ = mib.Bytes(p)
		}
		n.Caps = CDPCaps(bits, n.Platform)
		sw.Neighbors = append(sw.Neighbors, n)
	}
}

var ciscoAP = regexp.MustCompile(`(?i)\bAIR-|AIRONET|\bC91\d\d`)

// CDPCaps decodes cdpCacheCapabilities (CDP capability bits, network byte order): 0x01 router,
// 0x02 transparent bridge, 0x04 source-route bridge, 0x08 switch, 0x10 host, 0x40 repeater,
// 0x80 VoIP phone. Cisco access points report bridge bits, so the platform identifies them.
func CDPCaps(b []byte, platform string) Caps {
	var v uint32
	for _, x := range b {
		v = v<<8 | uint32(x)
	}
	return Caps{
		Router:   v&0x01 != 0,
		Bridge:   v&0x0e != 0,
		Station:  v&0x10 != 0,
		Repeater: v&0x40 != 0,
		Phone:    v&0x80 != 0 || strings.Contains(strings.ToLower(platform), "phone"),
		AP:       ciscoAP.MatchString(platform),
	}
}
