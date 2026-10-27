// Package inventory reads device lists. Two CSV layouts are accepted, line by line:
//
//	role,host[,alias[,version[,community]]]     role is switch or arp (alias: router)
//	host,alias,version,read_community[,write]  Switch Port Mapper's import format; role switch
//
// A header line naming the columns (role,host,alias,version,community in any order) may come
// first. Blank lines and lines starting with # are ignored. The write community, if present,
// is ignored: mapping is read-only.
package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// Device is one inventory line.
type Device struct {
	Role      string // switch or arp
	Host      string
	Alias     string
	Version   string // empty: use the command-line default
	Community string // empty: use the command-line default
	Line      int
}

// Parse reads an inventory. A UTF-8 byte-order mark (Excel on Windows) is ignored, and text
// after " #" (outside quotes) is a comment.
func Parse(r io.Reader) ([]Device, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return nil, err
	}
	text := strings.TrimPrefix(string(raw), "\ufeff")
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = stripComment(l)
	}
	cr := csv.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.Comment = '#'
	var out []Device
	var header map[string]int
	first := true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		line, _ := cr.FieldPos(0)
		for i := range rec {
			rec[i] = strings.TrimSpace(rec[i])
		}
		if len(rec) == 0 || (len(rec) == 1 && rec[0] == "") {
			continue
		}
		if first {
			first = false
			if h := headerOf(rec); h != nil {
				header = h
				continue
			}
		}
		var d Device
		switch {
		case header != nil:
			col := func(name string) string {
				if i, ok := header[name]; ok && i < len(rec) {
					return rec[i]
				}
				return ""
			}
			d = Device{Role: col("role"), Host: col("host"), Alias: col("alias"), Version: col("version"), Community: col("community")}
			if d.Role == "" {
				d.Role = "switch"
			}
		case isRole(rec[0]):
			d = Device{Role: rec[0], Host: at(rec, 1), Alias: at(rec, 2), Version: at(rec, 3), Community: at(rec, 4)}
		default:
			d = Device{Role: "switch", Host: rec[0], Alias: at(rec, 1), Version: at(rec, 2), Community: at(rec, 3)}
		}
		d.Line = line
		d.Role = strings.ToLower(d.Role)
		if d.Role == "router" {
			d.Role = "arp"
		}
		if d.Role != "switch" && d.Role != "arp" {
			return nil, fmt.Errorf("line %d: unknown role %q (switch or arp)", line, d.Role)
		}
		if d.Host == "" {
			return nil, fmt.Errorf("line %d: no host", line)
		}
		out = append(out, d)
	}
	return out, nil
}

// stripComment cuts a line at the first " #" or "\t#" outside double quotes.
func stripComment(line string) string {
	quoted := false
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '"':
			quoted = !quoted
		case c == '#' && !quoted && i > 0 && (line[i-1] == ' ' || line[i-1] == '\t'):
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return line
}

func headerOf(rec []string) map[string]int {
	h := map[string]int{}
	for i, f := range rec {
		f = strings.ToLower(f)
		switch f {
		case "role", "host", "alias", "version", "community":
			h[f] = i
		}
	}
	if _, ok := h["host"]; !ok {
		return nil
	}
	return h
}

func isRole(s string) bool {
	switch strings.ToLower(s) {
	case "switch", "arp", "router":
		return true
	}
	return false
}

func at(rec []string, i int) string {
	if i < len(rec) {
		return rec[i]
	}
	return ""
}
