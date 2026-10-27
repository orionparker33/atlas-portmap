package gui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/engine"
	"github.com/orionparker33/atlas-portmap/internal/inventory"
	"github.com/orionparker33/atlas-portmap/internal/macaddr"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
)

// scanRequest is the GUI's scan form. Secrets left empty fall back to the PORTMAP_*
// environment variables of the process that started the GUI.
type scanRequest struct {
	Label     string `json:"label"`
	Switches  string `json:"switches"`
	ARP       string `json:"arp"`
	Inventory string `json:"inventory"`
	SNMP      struct {
		Version     string `json:"version"`
		Community   string `json:"community"`
		Port        int    `json:"port"`
		TimeoutMS   int    `json:"timeout_ms"`
		Retries     int    `json:"retries"`
		MaxReps     int    `json:"max_reps"`
		V3User      string `json:"v3_user"`
		V3AuthProto string `json:"v3_auth_proto"`
		V3AuthPass  string `json:"v3_auth_pass"`
		V3PrivProto string `json:"v3_priv_proto"`
		V3PrivPass  string `json:"v3_priv_pass"`
		V3Context   string `json:"v3_context"`
	} `json:"snmp"`
	Options struct {
		CiscoPerVLAN    string `json:"cisco_per_vlan"`
		VLANs           string `json:"vlans"`
		LLDP            bool   `json:"lldp"`
		CDP             bool   `json:"cdp"`
		Dot1x           bool   `json:"dot1x"`
		Columns         string `json:"columns"`
		UplinkThreshold int    `json:"uplink_threshold"`
		AllSightings    bool   `json:"all_sightings"`
		AllPorts        bool   `json:"all_ports"`
		Resolve         bool   `json:"resolve"`
		ARPFromSwitches bool   `json:"arp_from_switches"`
		LocalARP        bool   `json:"local_arp"`
		Concurrency     int    `json:"concurrency"`
		MACFormat       string `json:"mac_format"`
	} `json:"options"`
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func inRange(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("%s must be between %d and %d", name, lo, hi)
	}
	return nil
}

func (sr scanRequest) build() (engine.Request, error) {
	var req engine.Request
	sn, op := sr.SNMP, sr.Options
	fallback := func(v *string, env string) {
		if *v == "" {
			*v = os.Getenv(env)
		}
	}
	fallback(&sn.Community, "PORTMAP_COMMUNITY")
	fallback(&sn.V3User, "PORTMAP_V3_USER")
	fallback(&sn.V3AuthPass, "PORTMAP_V3_AUTH_PASS")
	fallback(&sn.V3PrivPass, "PORTMAP_V3_PRIV_PASS")
	ver, err := snmpc.ParseVersion(sn.Version)
	if err != nil {
		return req, err
	}
	defaulted := sn.Community == "" && ver != snmpc.V3
	if defaulted {
		sn.Community = "public"
	}
	sn.Port, sn.TimeoutMS, sn.MaxReps = orDefault(sn.Port, 161), orDefault(sn.TimeoutMS, 3000), orDefault(sn.MaxReps, 25)
	op.Concurrency = orDefault(op.Concurrency, 8)
	for _, c := range []error{
		inRange("port", sn.Port, 1, 65535), inRange("timeout", sn.TimeoutMS, 100, 60000), inRange("retries", sn.Retries, 0, 5),
		inRange("max-repetitions", sn.MaxReps, 1, 500), inRange("concurrency", op.Concurrency, 1, 64),
		inRange("uplink threshold", op.UplinkThreshold, 0, 100000),
	} {
		if c != nil {
			return req, c
		}
	}
	if op.MACFormat == "" {
		op.MACFormat = "colon"
	}
	if !contains(macaddr.Styles, op.MACFormat) {
		return req, fmt.Errorf("unknown MAC format %q", op.MACFormat)
	}
	if op.CiscoPerVLAN == "" {
		op.CiscoPerVLAN = "auto"
	}
	if !contains([]string{"auto", "on", "off"}, op.CiscoPerVLAN) {
		return req, fmt.Errorf("Cisco per-VLAN must be auto, on or off")
	}
	cfg := snmpc.Config{
		Port: uint16(sn.Port), Version: ver, Community: sn.Community, CommunityDefaulted: defaulted,
		V3User: sn.V3User, V3AuthProto: sn.V3AuthProto, V3AuthPass: sn.V3AuthPass,
		V3PrivProto: sn.V3PrivProto, V3PrivPass: sn.V3PrivPass, V3Context: sn.V3Context,
		Timeout: time.Duration(sn.TimeoutMS) * time.Millisecond, Retries: sn.Retries, MaxRepetitions: uint32(sn.MaxReps),
	}
	var inv []inventory.Device
	if strings.TrimSpace(sr.Inventory) != "" {
		if inv, err = inventory.Parse(strings.NewReader(sr.Inventory)); err != nil {
			return req, fmt.Errorf("inventory: %w", err)
		}
	}
	sw, arp, err := engine.Devices(cfg, engine.Hosts(sr.Switches), engine.Hosts(sr.ARP), inv)
	if err != nil {
		return req, err
	}
	if len(sw) == 0 {
		return req, errNoSwitch
	}
	if len(sw)+len(arp) > 1000 {
		return req, fmt.Errorf("too many devices (%d); split the scan", len(sw)+len(arp))
	}
	vlans, err := engine.ParseVLANs(op.VLANs)
	if err != nil {
		return req, err
	}
	cols, err := engine.ParseColumns(strings.Split(op.Columns, "\n"))
	if err != nil {
		return req, err
	}
	copt := collect.DefaultOptions()
	copt.CiscoPerVLAN, copt.VLANs, copt.LLDP, copt.CDP, copt.Dot1x, copt.Columns = op.CiscoPerVLAN, vlans, op.LLDP, op.CDP, op.Dot1x, cols
	return engine.Request{
		Label: cleanLabel(sr.Label), Switches: sw, ARPSources: arp,
		ARPFromSwitches: op.ARPFromSwitches, LocalARP: op.LocalARP, Collect: copt,
		UplinkThreshold: op.UplinkThreshold, AllSightings: op.AllSightings, AllPorts: op.AllPorts,
		MACFormat: op.MACFormat, Resolve: op.Resolve, Concurrency: op.Concurrency,
	}, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
