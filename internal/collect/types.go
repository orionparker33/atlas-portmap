// Package collect reads the SNMP tables atlas-portmap joins: interfaces, the bridge
// forwarding database, VLANs, LLDP/CDP neighbours, 802.1X state and ARP caches.
package collect

import (
	"fmt"
	"net"
	"strings"
)

// FDB entry status, shared by dot1dTpFdbStatus and dot1qTpFdbStatus (RFC 4188, RFC 4363).
const (
	FDBOther   = 1
	FDBInvalid = 2
	FDBLearned = 3
	FDBSelf    = 4
	FDBMgmt    = 5
)

// Interface is one IF-MIB row.
type Interface struct {
	IfIndex   int
	Name      string // ifName (Gi1/0/1)
	Descr     string // ifDescr (GigabitEthernet1/0/1)
	Alias     string // ifAlias, or CISCO-STACK-MIB portName when ifAlias is empty
	Type      int    // IANAifType
	Admin     int    // ifAdminStatus: 1 up, 2 down, 3 testing
	Oper      int    // ifOperStatus: 1 up, 2 down, 3 testing, 5 dormant, 6 notPresent, 7 lowerLayerDown
	SpeedMbps uint64 // ifHighSpeed
}

// Label is the best short name for the port.
func (i *Interface) Label() string {
	switch {
	case i.Name != "":
		return i.Name
	case i.Descr != "":
		return i.Descr
	}
	return fmt.Sprintf("ifIndex %d", i.IfIndex)
}

// Physical reports Ethernet-like interface types (front-panel ports rather than VLAN
// interfaces, loopbacks, tunnels or port-channels).
func (i *Interface) Physical() bool {
	switch i.Type {
	case 6, 7, 62, 69, 117: // ethernetCsmacd, iso88023Csmacd, fastEther, fastEtherFX, gigabitEthernet
		return true
	}
	return false
}

// Status summarises admin and operational state.
func (i *Interface) Status() string {
	if i.Admin == 2 {
		return "disabled"
	}
	switch i.Oper {
	case 1:
		return "up"
	case 2, 6, 7:
		return "down"
	case 3:
		return "testing"
	case 5:
		return "dormant"
	}
	return ""
}

// FDBEntry is one learned address.
type FDBEntry struct {
	MAC        net.HardwareAddr
	BridgePort int
	IfIndex    int // 0: resolve through Switch.BridgePortIfIndex
	VLAN       int // 0: unknown, resolve through the port's PVID
	Status     int // 0 when the agent does not report one
}

// Caps are a neighbour's advertised system capabilities.
type Caps struct {
	Bridge, Router, Phone, AP, Station, Repeater, Other bool
}

func (c Caps) String() string {
	var s []string
	for _, f := range []struct {
		on   bool
		name string
	}{{c.Bridge, "bridge"}, {c.Router, "router"}, {c.Phone, "phone"}, {c.AP, "ap"}, {c.Station, "station"}, {c.Repeater, "repeater"}, {c.Other, "other"}} {
		if f.on {
			s = append(s, f.name)
		}
	}
	return strings.Join(s, ",")
}

// Neighbor is an LLDP or CDP neighbour seen on a local port.
type Neighbor struct {
	IfIndex    int    // local ifIndex; 0 when it could not be resolved
	LocalPort  int    // lldpRemLocalPortNum (LLDP) or cdpCacheIfIndex (CDP)
	Protocol   string // "lldp" or "cdp"
	SysName    string
	ChassisID  string
	PortID     string
	PortDesc   string
	Platform   string
	Caps       Caps
	ResolvedBy string // how the local port was mapped to an ifIndex
}

// LocalSource is the ARPEntry.Source of entries read from this machine's own neighbour cache.
const LocalSource = "local"

// ARPEntry is one IP-to-MAC binding. VLAN is the VLAN the binding was learned in, 0 when unknown;
// VLANBy says how it was found: "ifname" (the agent's VLAN interface name), "fdb" (every other
// address on the same interface sits in that one VLAN) or "own-mac" (local cache: this machine's
// own MAC on that interface sits in that one VLAN).
type ARPEntry struct {
	IP      net.IP
	MAC     net.HardwareAddr
	IfIndex int
	Iface   string // the agent's ifName/ifDescr for IfIndex, or the local OS interface
	Source  string
	VLAN    int
	VLANBy  string
}

// Column is an extra per-port value: a numeric OID whose rows are indexed by ifIndex.
type Column struct {
	Name string
	OID  string
}

// Options controls what CollectSwitch reads.
type Options struct {
	CiscoPerVLAN string // auto (Cisco without Q-BRIDGE FDB), on, off
	VLANs        []int  // VLANs for per-VLAN collection; empty means discover via CISCO-VTP-MIB
	LLDP         bool
	CDP          bool
	Dot1x        bool
	VLANNames    bool
	Columns      []Column
}

// DefaultOptions is what the CLI uses unless told otherwise.
func DefaultOptions() Options {
	return Options{CiscoPerVLAN: "auto", LLDP: true, CDP: true, VLANNames: true}
}

// Switch is everything read from one switch.
type Switch struct {
	Target            string
	Addr              string // the agent's IP address as dialled (a resolved hostname)
	Alias             string // operator-supplied display name (inventory)
	SysName           string
	SysDescr          string
	SysObjectID       string
	Enterprise        int // IANA PEN from sysObjectID, -1 when unknown
	BaseMAC           net.HardwareAddr
	Interfaces        map[int]*Interface
	BridgePortIfIndex map[int]int    // dot1dBasePort -> ifIndex
	Stack             map[int][]int  // ifIndex -> ifIndexes layered on it (LAG, Junos logical unit)
	PVID              map[int]int    // dot1dBasePort -> port VLAN ID
	Egress            map[int][]int  // dot1dBasePort -> VLANs it forwards (dot1qVlanCurrentEgressPorts)
	Untagged          map[int][]int  // dot1dBasePort -> VLANs it sends untagged
	VLANNames         map[int]string // VLAN ID -> name
	FDB               []FDBEntry
	FDBSource         string // q-bridge, bridge, cisco-per-vlan; empty when no FDB was readable
	Neighbors         []Neighbor
	LLDPSeen          bool
	Dot1x             map[int]int               // ifIndex -> dot1xAuthAuthControlledPortControl
	Extra             map[string]map[int]string // column -> ifIndex -> value
	Warnings          []string
}

func newSwitch(target string) *Switch {
	return &Switch{
		Target:            target,
		Enterprise:        -1,
		Interfaces:        map[int]*Interface{},
		BridgePortIfIndex: map[int]int{},
		Stack:             map[int][]int{},
		PVID:              map[int]int{},
		Egress:            map[int][]int{},
		Untagged:          map[int][]int{},
		VLANNames:         map[int]string{},
		Dot1x:             map[int]int{},
		Extra:             map[string]map[int]string{},
	}
}

// Name is the display name: the inventory alias, else sysName, else the target.
func (s *Switch) Name() string {
	switch {
	case s.Alias != "":
		return s.Alias
	case s.SysName != "":
		return s.SysName
	}
	return s.Target
}

func (s *Switch) warnf(format string, a ...any) {
	s.Warnings = append(s.Warnings, fmt.Sprintf(format, a...))
}
