package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/inventory"
	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
)

// Hosts splits a free-form host list (newlines, commas or spaces; # starts a comment).
func Hosts(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, f := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' }) {
			out = append(out, f)
		}
	}
	return out
}

// Devices turns host lists and an inventory into switch and ARP device lists. Inventory lines
// override def's version and community.
func Devices(def snmpc.Config, switches, arps []string, inv []inventory.Device) ([]Device, []Device, error) {
	if err := def.Validate(); err != nil {
		return nil, nil, err
	}
	var sw, arp []Device
	for _, h := range switches {
		sw = append(sw, Device{Host: h, Config: def})
	}
	for _, h := range arps {
		arp = append(arp, Device{Host: h, Config: def})
	}
	for _, d := range inv {
		c := def
		if d.Version != "" {
			v, err := snmpc.ParseVersion(d.Version)
			if err != nil {
				return nil, nil, fmt.Errorf("inventory line %d: %w", d.Line, err)
			}
			c.Version = v
		}
		if d.Community != "" {
			c.Community, c.CommunityDefaulted = d.Community, false
		}
		if err := c.Validate(); err != nil {
			return nil, nil, fmt.Errorf("inventory line %d (%s): %w", d.Line, d.Host, err)
		}
		dev := Device{Host: d.Host, Alias: d.Alias, Config: c}
		if d.Role == "arp" {
			arp = append(arp, dev)
		} else {
			sw = append(sw, dev)
		}
	}
	for _, d := range append(append([]Device(nil), sw...), arp...) {
		if _, _, err := snmpc.SplitTarget(d.Host, def.Port); err != nil {
			return nil, nil, err
		}
	}
	return sw, arp, nil
}

// ParseVLANs reads "1,10-20,30" into sorted, unique VLAN IDs.
func ParseVLANs(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	set := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		b := a
		if err == nil && isRange {
			b, err = strconv.Atoi(strings.TrimSpace(hi))
		}
		if err != nil || a < 1 || b > 4094 || a > b {
			return nil, fmt.Errorf("bad VLAN list entry %q (VLAN IDs 1-4094, ranges like 10-20)", part)
		}
		for v := a; v <= b; v++ {
			set[v] = true
		}
	}
	out := make([]int, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

// ParseColumns reads NAME=OID specs (numeric OIDs indexed by ifIndex).
func ParseColumns(specs []string) ([]collect.Column, error) {
	var out []collect.Column
	seen := map[string]bool{}
	for _, s := range specs {
		if strings.TrimSpace(s) == "" {
			continue
		}
		name, oid, ok := strings.Cut(s, "=")
		name, oid = strings.TrimSpace(name), strings.TrimSpace(oid)
		if !ok || name == "" || !mib.ValidOID(oid) {
			return nil, fmt.Errorf("bad column %q: want NAME=numeric.oid", s)
		}
		if seen[strings.ToLower(name)] {
			return nil, fmt.Errorf("duplicate column name %q", name)
		}
		seen[strings.ToLower(name)] = true
		out = append(out, collect.Column{Name: name, OID: mib.Norm(oid)})
	}
	return out, nil
}
