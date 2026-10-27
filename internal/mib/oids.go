// Package mib holds the SNMP object identifiers atlas-portmap reads and the helpers that
// decode their row indexes and values. Every OID below is from a published MIB, cited inline.
package mib

// SNMPv2-MIB (RFC 3418): system group scalars.
const (
	SysDescr    = "1.3.6.1.2.1.1.1.0"
	SysObjectID = "1.3.6.1.2.1.1.2.0"
	SysName     = "1.3.6.1.2.1.1.5.0"
)

// IF-MIB (RFC 2863): ifTable and ifXTable columns, indexed by ifIndex.
const (
	IfDescr       = "1.3.6.1.2.1.2.2.1.2"
	IfType        = "1.3.6.1.2.1.2.2.1.3"
	IfAdminStatus = "1.3.6.1.2.1.2.2.1.7"
	IfOperStatus  = "1.3.6.1.2.1.2.2.1.8"
	IfName        = "1.3.6.1.2.1.31.1.1.1.1"
	IfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"
	IfAlias       = "1.3.6.1.2.1.31.1.1.1.18"
	IfStackStatus = "1.3.6.1.2.1.31.1.2.1.3" // index: ifStackHigherLayer.ifStackLowerLayer
)

// IEEE8023-LAG-MIB: the aggregator a LAG member is attached to (index: member ifIndex).
const Dot3adAggPortAttachedAggID = "1.2.840.10006.300.43.1.2.1.1.13"

// BRIDGE-MIB (RFC 4188).
const (
	Dot1dBaseBridgeAddress = "1.3.6.1.2.1.17.1.1.0"
	Dot1dBasePortIfIndex   = "1.3.6.1.2.1.17.1.4.1.2" // index: dot1dBasePort
	Dot1dTpFdbPort         = "1.3.6.1.2.1.17.4.3.1.2" // index: MAC (6 sub-ids)
	Dot1dTpFdbStatus       = "1.3.6.1.2.1.17.4.3.1.3"
)

// Q-BRIDGE-MIB (RFC 4363): VLAN-aware forwarding database.
const (
	Dot1qTpFdbPort   = "1.3.6.1.2.1.17.7.1.2.2.1.2" // index: dot1qFdbId.MAC
	Dot1qTpFdbStatus = "1.3.6.1.2.1.17.7.1.2.2.1.3"
	Dot1qVlanFdbId   = "1.3.6.1.2.1.17.7.1.4.2.1.3" // index: dot1qVlanTimeMark.dot1qVlanIndex
	// PortList bitmaps, same index as Dot1qVlanFdbId: the first octet's MSB is dot1dBasePort 1.
	Dot1qVlanCurrentEgressPorts   = "1.3.6.1.2.1.17.7.1.4.2.1.4"
	Dot1qVlanCurrentUntaggedPorts = "1.3.6.1.2.1.17.7.1.4.2.1.5"
	Dot1qVlanStaticName           = "1.3.6.1.2.1.17.7.1.4.3.1.1" // index: dot1qVlanIndex
	Dot1qPvid                     = "1.3.6.1.2.1.17.7.1.4.5.1.1" // index: dot1dBasePort
)

// IP-MIB (RFC 4293): ARP / IPv6 neighbour tables.
const (
	IpNetToMediaPhysAddress    = "1.3.6.1.2.1.4.22.1.2" // index: ifIndex.a.b.c.d
	IpNetToMediaType           = "1.3.6.1.2.1.4.22.1.4"
	IpNetToPhysicalPhysAddress = "1.3.6.1.2.1.4.35.1.4" // index: ifIndex.addrType.len.addr…
	IpNetToPhysicalType        = "1.3.6.1.2.1.4.35.1.6"
)

// LLDP-MIB (IEEE 802.1AB-2005).
const (
	LldpLocPortIdSubtype    = "1.0.8802.1.1.2.1.3.7.1.2" // index: lldpLocPortNum
	LldpLocPortId           = "1.0.8802.1.1.2.1.3.7.1.3"
	LldpLocPortDesc         = "1.0.8802.1.1.2.1.3.7.1.4"
	LldpRemChassisIdSubtype = "1.0.8802.1.1.2.1.4.1.1.4" // index: timeMark.localPortNum.remIndex
	LldpRemChassisId        = "1.0.8802.1.1.2.1.4.1.1.5"
	LldpRemPortIdSubtype    = "1.0.8802.1.1.2.1.4.1.1.6"
	LldpRemPortId           = "1.0.8802.1.1.2.1.4.1.1.7"
	LldpRemPortDesc         = "1.0.8802.1.1.2.1.4.1.1.8"
	LldpRemSysName          = "1.0.8802.1.1.2.1.4.1.1.9"
	LldpRemSysCapEnabled    = "1.0.8802.1.1.2.1.4.1.1.12"
)

// IEEE8021-PAE-MIB (802.1X): authenticator port control, indexed by dot1xPaePortNumber
// (an InterfaceIndex).
const Dot1xAuthAuthControlledPortControl = "1.0.8802.1.1.1.1.2.1.1.6"

// CISCO-CDP-MIB: neighbour cache, indexed by cdpCacheIfIndex.cdpCacheDeviceIndex.
const (
	CdpCacheDeviceId     = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
	CdpCacheDevicePort   = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
	CdpCachePlatform     = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"
	CdpCacheCapabilities = "1.3.6.1.4.1.9.9.23.1.2.1.1.9"
)

// CISCO-VTP-MIB: the VLANs a Cisco switch knows, used to reach its per-VLAN BRIDGE-MIB
// instances. Index: managementDomainIndex.vtpVlanIndex.
const (
	VtpVlanState = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
	VtpVlanType  = "1.3.6.1.4.1.9.9.46.1.3.1.1.3"
)

// CISCO-STACK-MIB: port names on CatOS and older IOS. Index: portModuleIndex.portIndex.
const (
	CiscoPortName    = "1.3.6.1.4.1.9.5.1.4.1.1.4"
	CiscoPortIfIndex = "1.3.6.1.4.1.9.5.1.4.1.1.11"
)

// JUNIPER-L2ALD-VLAN-MIB / JUNIPER-VLAN-MIB: Junos numbers Q-BRIDGE VLANs by an internal index;
// these map it (and the FDB ID) to the 802.1Q tag. Index: the internal VLAN index.
const (
	JnxL2aldVlanTag   = "1.3.6.1.4.1.2636.3.48.1.3.1.1.3"
	JnxL2aldVlanFdbID = "1.3.6.1.4.1.2636.3.48.1.3.1.1.5"
	JnxExVlanTag      = "1.3.6.1.4.1.2636.3.40.1.5.1.5.1.5"
)

// IANA Private Enterprise Numbers used for vendor-specific handling (sysObjectID 1.3.6.1.4.1.N.…).
const (
	EnterpriseCisco   = 9
	EnterpriseJuniper = 2636
)
