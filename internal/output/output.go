// Package output renders a port map as an aligned table, JSON or CSV.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/orionparker33/atlas-portmap/internal/portmap"
)

// SwitchSummary describes one switch in the report.
type SwitchSummary struct {
	Target      string   `json:"target"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	SysObjectID string   `json:"sys_object_id,omitempty"`
	Vendor      string   `json:"vendor,omitempty"`
	FDBSource   string   `json:"fdb_source,omitempty"`
	FDBRows     int      `json:"fdb_rows"`
	Partial     bool     `json:"partial,omitempty"` // answered, then stopped part-way (see error)
	LLDP        bool     `json:"lldp"`
	Warnings    []string `json:"warnings,omitempty"`
	Error       string   `json:"error,omitempty"`      // the raw error
	ErrorKind   string   `json:"error_kind,omitempty"` // its class: no-response, auth-failed, access-denied, … (snmpc.Kind)
	Hint        string   `json:"hint,omitempty"`       // what to check or change
}

// SourceSummary describes one ARP source.
type SourceSummary struct {
	Target    string `json:"target"`
	Entries   int    `json:"entries"`
	Error     string `json:"error,omitempty"`
	ErrorKind string `json:"error_kind,omitempty"`
	Hint      string `json:"hint,omitempty"`
}

// WriteFailures writes one error line per switch that failed or stopped part-way and per ARP
// source that failed: the hint (what to check) first, then the raw cause. They are errors, not
// warnings, so the CLI prints them even with -q. A partial switch says so, because its rows look
// complete.
func WriteFailures(w io.Writer, r *Report) {
	for _, s := range r.Switches {
		if s.Error == "" {
			continue
		}
		who := s.Target
		if s.Name != "" && s.Name != s.Target {
			who = fmt.Sprintf("%s (%s)", s.Name, s.Target)
		}
		state := "FAILED (no data)"
		if s.Partial {
			state = fmt.Sprintf("PARTIAL (stopped part-way after %d FDB rows; its rows are incomplete)", s.FDBRows)
		}
		failure(w, "switch "+who, state, s.ErrorKind, s.Hint, s.Error)
	}
	for _, s := range r.ARPSources {
		if s.Error != "" {
			failure(w, "ARP source "+s.Target, "FAILED (IP addresses from it are missing)", s.ErrorKind, s.Hint, s.Error)
		}
	}
}

func failure(w io.Writer, who, state, kind, hint, raw string) {
	if kind != "" && kind != "other" {
		state += " [" + kind + "]"
	}
	if hint == "" {
		fmt.Fprintf(w, "error: %s: %s: %s\n", plain(who), state, plain(raw))
		return
	}
	fmt.Fprintf(w, "error: %s: %s: %s\n  cause: %s\n", plain(who), state, plain(hint), plain(raw))
}

// plain replaces control characters (a sysName can carry terminal escapes) with spaces.
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}

// Report is everything one run produced.
type Report struct {
	Tool       string          `json:"tool"`
	Version    string          `json:"version"`
	Label      string          `json:"label,omitempty"` // client / site the map belongs to
	Generated  string          `json:"generated"`
	Warnings   []string        `json:"warnings,omitempty"`
	Switches   []SwitchSummary `json:"switches"`
	ARPSources []SourceSummary `json:"arp_sources"`
	Entries    []portmap.Entry `json:"entries"`
}

// Formats lists the accepted output formats.
var Formats = []string{"table", "json", "csv"}

// Write renders r in format.
func Write(w io.Writer, format string, r *Report) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "csv":
		return writeCSV(w, r.Entries)
	case "table", "":
		return writeTable(w, r.Entries)
	}
	return fmt.Errorf("unknown output format %q (table, json or csv)", format)
}

func extraColumns(entries []portmap.Entry) []string {
	set := map[string]bool{}
	for _, e := range entries {
		for k := range e.Extra {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func writeTable(w io.Writer, entries []portmap.Entry) error {
	var alias, host, dot1x bool
	for _, e := range entries {
		alias = alias || e.PortAlias != ""
		host = host || len(e.Hostnames) > 0
		dot1x = dot1x || e.Dot1x != ""
	}
	extras := extraColumns(entries)
	head := []string{"SWITCH", "PORT"}
	if alias {
		head = append(head, "ALIAS")
	}
	head = append(head, "VLAN", "MAC", "VENDOR", "IP")
	if host {
		head = append(head, "HOSTNAME")
	}
	head = append(head, "STATUS")
	if dot1x {
		head = append(head, "802.1X")
	}
	for _, x := range extras {
		head = append(head, strings.ToUpper(x))
	}
	head = append(head, "NOTE")

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, e := range entries {
		row := []string{e.Switch, e.Port}
		if alias {
			row = append(row, e.PortAlias)
		}
		vlan := ""
		if e.VLAN > 0 {
			vlan = strconv.Itoa(e.VLAN)
		}
		row = append(row, vlan, e.MAC, truncate(e.Vendor, 30), strings.Join(e.IPs, ","))
		if host {
			row = append(row, strings.Join(e.Hostnames, ","))
		}
		row = append(row, e.PortStatus)
		if dot1x {
			row = append(row, e.Dot1x)
		}
		for _, x := range extras {
			row = append(row, e.Extra[x])
		}
		row = append(row, note(e))
		for i := range row {
			row[i] = cell(row[i])
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	return tw.Flush()
}

func note(e portmap.Entry) string {
	var n []string
	if e.MAC == "" {
		if e.MACsOnPort == 0 {
			n = append(n, "no MACs")
		} else {
			n = append(n, fmt.Sprintf("%d MACs, placed elsewhere", e.MACsOnPort))
		}
	}
	if e.Secondary {
		n = append(n, "secondary sighting")
	}
	switch e.PortMode {
	case "trunk":
		t := "trunk: tagged " + e.TaggedVLANs
		if e.NativeVLAN > 0 {
			t += fmt.Sprintf("; native %d", e.NativeVLAN)
		}
		n = append(n, t)
	case "hybrid":
		t := "hybrid: untagged " + e.UntaggedVLANs
		if e.TaggedVLANs != "" {
			t += "; tagged " + e.TaggedVLANs
		}
		if e.NativeVLAN > 0 {
			t += fmt.Sprintf("; native %d", e.NativeVLAN)
		}
		n = append(n, t)
	}
	if e.SwitchMAC != "" {
		n = append(n, "MAC of switch "+e.SwitchMAC)
	}
	if len(e.OtherIPs) > 0 {
		n = append(n, "other IPs: "+strings.Join(e.OtherIPs, ", "))
	}
	if e.Uplink {
		if e.UplinkKind == "" || e.UplinkKind == "switch" {
			n = append(n, "uplink: "+e.UplinkReason)
		} else {
			n = append(n, "shared port: "+e.UplinkReason)
		}
	}
	if e.Neighbor != "" {
		n = append(n, e.Neighbor)
	}
	return strings.Join(n, "; ")
}

// cell makes a value safe for a terminal table: control characters (which could carry escape
// sequences from a device-supplied string) become spaces; empty cells show "-".
func cell(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
	if s = strings.TrimSpace(s); s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func writeCSV(w io.Writer, entries []portmap.Entry) error {
	extras := extraColumns(entries)
	cw := csv.NewWriter(w)
	head := []string{"switch", "switch_addr", "port", "port_alias", "if_index", "bridge_port", "port_status", "speed_mbps",
		"vlan", "vlan_name", "mac", "vendor", "ips", "hostnames", "macs_on_port", "uplink", "uplink_reason", "neighbor",
		"dot1x", "secondary", "also_seen", "uplink_kind", "vlan_source", "member_of",
		"port_mode", "native_vlan", "tagged_vlans", "other_ips", "switch_mac", "untagged_vlans"}
	head = append(head, extras...)
	if err := cw.Write(head); err != nil {
		return err
	}
	num := func(n int) string {
		if n == 0 {
			return ""
		}
		return strconv.Itoa(n)
	}
	for _, e := range entries {
		speed := ""
		if e.SpeedMbps > 0 {
			speed = strconv.FormatUint(e.SpeedMbps, 10)
		}
		row := []string{
			e.Switch, e.SwitchAddr, e.Port, e.PortAlias, num(e.IfIndex), num(e.BridgePort),
			e.PortStatus, speed, num(e.VLAN), e.VLANName, e.MAC, e.Vendor, strings.Join(e.IPs, ";"),
			strings.Join(e.Hostnames, ";"), strconv.Itoa(e.MACsOnPort), strconv.FormatBool(e.Uplink),
			e.UplinkReason, e.Neighbor, e.Dot1x, strconv.FormatBool(e.Secondary), strings.Join(e.AlsoSeen, ";"),
			e.UplinkKind, e.VLANSource, e.MemberOf,
			e.PortMode, num(e.NativeVLAN), e.TaggedVLANs, strings.Join(e.OtherIPs, ";"), e.SwitchMAC, e.UntaggedVLANs,
		}
		for _, x := range extras {
			row = append(row, e.Extra[x])
		}
		for i := range row { // every cell: an imported report can put anything in any field
			row[i] = text(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// text neutralises spreadsheet formula injection: a value starting with = + - @ or a tab/CR
// would run as a formula when the CSV is opened in a spreadsheet, so it gets a leading
// apostrophe (OWASP CSV injection guidance). Applied to every cell, since a report opened in
// the GUI can carry anything in any field.
func text(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
