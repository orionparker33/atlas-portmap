// Command atlas-portmap maps switch ports to the devices behind them over SNMP: which MAC,
// IP, hostname and vendor sits on which port and VLAN, across a group of switches. It runs as a
// command-line tool or serves a local web GUI ("atlas-portmap gui").
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/engine"
	"github.com/orionparker33/atlas-portmap/internal/gui"
	"github.com/orionparker33/atlas-portmap/internal/inventory"
	"github.com/orionparker33/atlas-portmap/internal/macaddr"
	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/output"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
	"github.com/orionparker33/atlas-portmap/internal/vendordb"
)

var version = "dev"

// Exit codes.
const (
	exitOK      = 0
	exitFailed  = 1 // nothing could be mapped
	exitUsage   = 2
	exitPartial = 3 // some devices failed; the output covers the rest
)

// desktop reports whether a bare invocation should open the GUI (a double-clicked binary on
// Windows or macOS, or a Linux session with a display). Tests replace it.
var desktop = func() bool {
	switch runtime.GOOS {
	case "windows", "darwin":
		return true
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); stop() }() // a second Ctrl-C terminates at once
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		if desktop() {
			return cmdGUI(ctx, nil, stdout, stderr)
		}
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "map":
		return cmdMap(ctx, args[1:], stdout, stderr)
	case "gui":
		return cmdGUI(ctx, args[1:], stdout, stderr)
	case "walk":
		return cmdWalk(ctx, args[1:], stdout, stderr)
	case "vendor":
		return cmdVendor(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "atlas-portmap", version)
		return exitOK
	case "help", "-h", "-help", "--help":
		usage(stdout)
		return exitOK
	}
	if strings.HasPrefix(args[0], "-") || net.ParseIP(args[0]) != nil || strings.ContainsAny(args[0], ".:") {
		return cmdMap(ctx, args, stdout, stderr) // flags or a bare target mean "map"
	}
	fmt.Fprintf(stderr, "atlas-portmap: unknown command %q\n\n", args[0])
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprint(w, `atlas-portmap maps switch ports to the devices behind them over SNMP.

Usage:
  atlas-portmap gui [flags]                  local web interface (the default when started from a desktop)
  atlas-portmap [map] [flags] [switch ...]   map one or more switches from the command line
  atlas-portmap walk [flags] HOST [OID ...]  walk OIDs on a device (diagnostics)
  atlas-portmap vendor MAC|sysObjectID ...   look up a MAC vendor or SNMP enterprise
  atlas-portmap version

Examples:
  PORTMAP_COMMUNITY=$(op read 'op://<vault>/<item>/community') atlas-portmap gui
  PORTMAP_COMMUNITY=… atlas-portmap -arp 10.0.0.1 10.0.0.2 10.0.0.3
  atlas-portmap -inventory devices.csv -label "Contoso HQ" -o json > map.json
  PORTMAP_V3_USER=mapper PORTMAP_V3_AUTH_PASS=… PORTMAP_V3_PRIV_PASS=… \
    atlas-portmap -v 3 -all-ports core-sw.lab

Secrets come from the environment: PORTMAP_COMMUNITY, PORTMAP_V3_AUTH_PASS,
PORTMAP_V3_PRIV_PASS (the SNMPv3 user from PORTMAP_V3_USER or -v3-user; it is not secret
and shows in error hints). "atlas-portmap map -h" lists every flag.

Exit status: 0 complete; 1 nothing mapped (no switch answered); 2 usage error;
3 partial (a switch failed or stopped part-way, an ARP source failed, or the run was
interrupted): the output covers what was read. Failed devices are reported on stderr
even with -q.
`)
}

// parseFlags parses flags anywhere among the arguments: the flag package stops at the first
// positional argument, so "map 10.0.0.2 -o json" would otherwise take -o and json as switches
// (and look them up in DNS). "--" ends flag parsing.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if n := len(args) - len(rest); n > 0 && args[n-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// multiFlag is a repeatable, comma-splittable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*m = append(*m, s)
		}
	}
	return nil
}

type snmpFlags struct {
	version, community, user, authProto, authPass, privProto, privPass, context string
	port, maxReps                                                               uint
	timeout                                                                     time.Duration
	retries                                                                     int
}

func (f *snmpFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.version, "v", "2c", "SNMP version: 1, 2c or 3")
	fs.StringVar(&f.version, "snmp-version", "2c", "same as -v")
	fs.StringVar(&f.community, "c", "", "v1/v2c community (default public; prefer PORTMAP_COMMUNITY)")
	fs.StringVar(&f.community, "community", "", "same as -c")
	fs.UintVar(&f.port, "port", 161, "SNMP UDP port (a target's own :port wins)")
	fs.DurationVar(&f.timeout, "timeout", 3*time.Second, "per-request timeout")
	fs.IntVar(&f.retries, "retries", 1, "per-request retries")
	fs.UintVar(&f.maxReps, "max-reps", 25, "GETBULK max-repetitions (lower it for agents that drop large responses)")
	fs.StringVar(&f.user, "v3-user", "", "SNMPv3 user (or PORTMAP_V3_USER)")
	fs.StringVar(&f.authProto, "v3-auth-proto", "sha", "SNMPv3 auth: none, md5, sha, sha224, sha256, sha384, sha512")
	fs.StringVar(&f.authPass, "v3-auth-pass", "", "SNMPv3 auth passphrase (prefer PORTMAP_V3_AUTH_PASS)")
	fs.StringVar(&f.privProto, "v3-priv-proto", "aes", "SNMPv3 privacy: none, des, aes, aes192, aes256, aes192c, aes256c")
	fs.StringVar(&f.privPass, "v3-priv-pass", "", "SNMPv3 privacy passphrase (prefer PORTMAP_V3_PRIV_PASS)")
	fs.StringVar(&f.context, "v3-context", "", "SNMPv3 context name for the default instance")
}

func (f *snmpFlags) config(set map[string]bool, stderr io.Writer, quiet bool) (snmpc.Config, error) {
	for _, s := range []struct {
		dst *string
		env string
	}{{&f.community, "PORTMAP_COMMUNITY"}, {&f.user, "PORTMAP_V3_USER"}, {&f.authPass, "PORTMAP_V3_AUTH_PASS"}, {&f.privPass, "PORTMAP_V3_PRIV_PASS"}} {
		if *s.dst == "" {
			*s.dst = os.Getenv(s.env)
		}
	}
	if !quiet {
		for _, n := range []string{"c", "community", "v3-auth-pass", "v3-priv-pass"} {
			if set[n] {
				fmt.Fprintf(stderr, "warning: -%s on the command line is visible in process listings and shell history; use the PORTMAP_* environment variables\n", n)
			}
		}
	}
	v, err := snmpc.ParseVersion(f.version)
	if err != nil {
		return snmpc.Config{}, err
	}
	defaulted := false
	if f.community == "" && v != snmpc.V3 {
		f.community, defaulted = "public", true
	}
	if f.port == 0 || f.port > 65535 {
		return snmpc.Config{}, fmt.Errorf("-port %d out of range", f.port)
	}
	if f.maxReps == 0 || f.maxReps > 500 {
		return snmpc.Config{}, fmt.Errorf("-max-reps %d out of range (1-500)", f.maxReps)
	}
	c := snmpc.Config{
		Port: uint16(f.port), Version: v, Community: f.community,
		V3User: f.user, V3AuthProto: f.authProto, V3AuthPass: f.authPass,
		V3PrivProto: f.privProto, V3PrivPass: f.privPass, V3Context: f.context,
		Timeout: f.timeout, Retries: f.retries, MaxRepetitions: uint32(f.maxReps),
		CommunityDefaulted: defaulted,
	}
	return c, c.Validate()
}

func visited(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func cmdMap(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("map", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf snmpFlags
	sf.register(fs)
	var switches, arps, columns multiFlag
	fs.Var(&switches, "s", "switch to map, host[:port]; repeatable or comma-separated (positional arguments work too)")
	fs.Var(&switches, "switch", "same as -s")
	fs.Var(&arps, "arp", "router / L3 device to read ARP from; repeatable")
	inv := fs.String("inventory", "", "CSV device list (role,host,alias,version,community, or Switch Port Mapper's import format)")
	label := fs.String("label", "", "client / site name recorded in the report")
	arpFromSwitches := fs.Bool("arp-from-switches", true, "also read ARP from each switch (L3 switches know their subnets)")
	localARP := fs.Bool("local-arp", false, "also use this machine's ARP / neighbour cache")
	perVLAN := fs.String("cisco-per-vlan", "auto", "Cisco per-VLAN BRIDGE-MIB instances: auto, on or off")
	vlanList := fs.String("vlans", "", "VLAN IDs for per-VLAN collection, e.g. 1,10-20 (default: CISCO-VTP-MIB)")
	noLLDP := fs.Bool("no-lldp", false, "skip LLDP")
	noCDP := fs.Bool("no-cdp", false, "skip CDP")
	dot1x := fs.Bool("dot1x", false, "add the 802.1X port-control column")
	fs.Var(&columns, "column", "extra per-port column NAME=OID (numeric OID indexed by ifIndex); repeatable")
	threshold := fs.Int("uplink-threshold", 10, "treat a port with at least N MACs as an uplink (0 disables)")
	allSightings := fs.Bool("all-sightings", false, "list every port that learned each MAC, not only its best location")
	allPorts := fs.Bool("all-ports", false, "also list physical ports with no endpoint (free ports, uplinks)")
	resolve := fs.Bool("resolve", false, "reverse-DNS the IP addresses")
	format := fs.String("o", "table", "output format: table, json or csv")
	fs.StringVar(format, "output", "table", "same as -o")
	macFormat := fs.String("mac-format", "colon", "MAC style: colon, dash, dot or bare")
	concurrency := fs.Int("concurrency", 8, "devices queried at once")
	deadline := fs.Duration("deadline", 10*time.Minute, "overall time limit")
	progress := fs.Bool("progress", false, "report each device's progress on stderr")
	quiet := fs.Bool("q", false, "suppress warnings on stderr (failed and partial devices are still reported)")
	pos, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	bad := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "atlas-portmap: "+format+"\n", a...)
		return exitUsage
	}
	switches = append(switches, pos...)
	cfg, err := sf.config(visited(fs), stderr, *quiet)
	if err != nil {
		return bad("%v", err)
	}
	if !contains(output.Formats, *format) {
		return bad("unknown output format %q (table, json or csv)", *format)
	}
	if !contains(macaddr.Styles, *macFormat) {
		return bad("unknown -mac-format %q (colon, dash, dot or bare)", *macFormat)
	}
	if !contains([]string{"auto", "on", "off"}, *perVLAN) {
		return bad("-cisco-per-vlan must be auto, on or off")
	}
	if *concurrency < 1 {
		return bad("-concurrency must be at least 1")
	}
	vlans, err := engine.ParseVLANs(*vlanList)
	if err != nil {
		return bad("-vlans: %v", err)
	}
	cols, err := engine.ParseColumns(columns)
	if err != nil {
		return bad("-column: %v", err)
	}
	var devs []inventory.Device
	if *inv != "" {
		f, err := os.Open(*inv)
		if err != nil {
			return bad("%v", err)
		}
		devs, err = inventory.Parse(f)
		f.Close()
		if err != nil {
			return bad("%s: %v", *inv, err)
		}
	}
	sw, arp, err := engine.Devices(cfg, switches, arps, devs)
	if err != nil {
		return bad("%v", err)
	}
	if len(sw) == 0 {
		return bad("no switches: give hosts as arguments, -s, or -inventory")
	}
	copt := collect.DefaultOptions()
	copt.CiscoPerVLAN, copt.VLANs, copt.LLDP, copt.CDP, copt.Dot1x, copt.Columns = *perVLAN, vlans, !*noLLDP, !*noCDP, *dot1x, cols
	req := engine.Request{
		Label: *label, Switches: sw, ARPSources: arp, ARPFromSwitches: *arpFromSwitches, LocalARP: *localARP, Collect: copt,
		UplinkThreshold: *threshold, AllSightings: *allSightings, AllPorts: *allPorts, MACFormat: *macFormat,
		Resolve: *resolve, Concurrency: *concurrency,
	}
	ctx, cancel := context.WithTimeout(ctx, *deadline)
	defer cancel()
	var onEvent func(engine.Event)
	if *progress {
		onEvent = func(e engine.Event) {
			if e.State == engine.StateQueued {
				return
			}
			line := fmt.Sprintf("[%-7s] %-9s %s", e.State, e.Role, e.Target)
			if e.Detail != "" {
				line += ": " + e.Detail
			}
			if e.Error != "" {
				line += ": " + e.Error
			}
			if e.ElapsedMS > 0 {
				line += fmt.Sprintf(" (%d ms)", e.ElapsedMS)
			}
			fmt.Fprintln(stderr, line)
		}
	}
	res := engine.Run(ctx, req, version, onEvent)
	rep := res.Report
	// -q drops warnings only. Failed and partial devices are errors and always reported: a
	// switch missing from the table, or one whose rows stop part-way, looks like a clean map.
	if !*quiet {
		for _, w := range rep.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
		for _, s := range rep.Switches {
			for _, w := range s.Warnings {
				fmt.Fprintf(stderr, "warning: switch %s: %s\n", firstNonEmpty(s.Name, s.Target), w)
			}
		}
	} else if res.Interrupted {
		fmt.Fprintln(stderr, "error: run interrupted before it finished; the map is incomplete")
	}
	output.WriteFailures(stderr, rep)
	if err := output.Write(stdout, *format, rep); err != nil {
		fmt.Fprintf(stderr, "atlas-portmap: %v\n", err)
		return exitFailed
	}
	switch {
	case res.SwitchesFailed == len(sw):
		return exitFailed
	case !res.Complete():
		return exitPartial
	}
	return exitOK
}

func cmdGUI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:0", "listen address (loopback by default; a random port unless given)")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser; use the printed link")
	allowRemote := fs.Bool("allow-remote", false, "allow a non-loopback -addr (plain HTTP: the token and typed credentials travel unencrypted; prefer ssh -L)")
	var opens multiFlag
	fs.Var(&opens, "open", "report (.json) to load at start; repeatable")
	pos, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	var pre []gui.Preload
	for _, p := range append(opens, pos...) {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "atlas-portmap gui: %v\n", err)
			return exitUsage
		}
		var r output.Report
		if err := json.Unmarshal(b, &r); err != nil || r.Tool != "atlas-portmap" {
			fmt.Fprintf(stderr, "atlas-portmap gui: %s is not an atlas-portmap JSON report\n", p)
			return exitUsage
		}
		pre = append(pre, gui.Preload{Name: filepath.Base(p), Report: &r})
	}
	err = gui.Serve(ctx, gui.Options{Addr: *addr, AllowRemote: *allowRemote, Version: version, OpenBrowser: !*noBrowser, Preload: pre, Stdout: stdout, Stderr: stderr})
	if err != nil {
		fmt.Fprintf(stderr, "atlas-portmap gui: %v\n", err)
		return exitFailed
	}
	return exitOK
}

func cmdWalk(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("walk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf snmpFlags
	sf.register(fs)
	target := fs.String("t", "", "device to walk (or the first argument)")
	quiet := fs.Bool("q", false, "suppress warnings")
	rest, err := parseFlags(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *target == "" && len(rest) > 0 {
		*target, rest = rest[0], rest[1:]
	}
	if *target == "" {
		fmt.Fprintln(stderr, "atlas-portmap walk: no device given")
		return exitUsage
	}
	if len(rest) == 0 {
		rest = []string{"1.3.6.1.2.1.1"} // system group
	}
	cfg, err := sf.config(visited(fs), stderr, *quiet)
	if err != nil {
		fmt.Fprintf(stderr, "atlas-portmap walk: %v\n", err)
		return exitUsage
	}
	sess, err := snmpc.Dial(ctx, *target, cfg, 0)
	if err != nil {
		fmt.Fprintf(stderr, "atlas-portmap walk: %s: %v\n", *target, err)
		return exitFailed
	}
	defer sess.Close()
	status := exitOK
	first := true
	for i, oid := range rest {
		if !mib.ValidOID(oid) {
			fmt.Fprintf(stderr, "atlas-portmap walk: %q is not a numeric OID\n", oid)
			status = exitUsage
			continue
		}
		var pdus []gosnmp.SnmpPDU
		read := func() (err error) {
			pdus, err = sess.Walk(mib.Norm(oid))
			if err == nil && len(pdus) == 0 {
				if p, ok, gerr := sess.Get(mib.Norm(oid)); gerr == nil && ok {
					pdus = append(pdus, p)
				} else if gerr != nil {
					err = gerr
				}
			}
			return err
		}
		if first { // one attempt before any retries, so wrong credentials cost one
			err, first = sess.FirstContact(read), false
		} else {
			err = read()
		}
		for _, p := range pdus { // rows read before an error are still printed
			fmt.Fprintf(stdout, "%s = %s: %s\n", mib.Norm(p.Name), mib.TypeName(p.Type), sanitize(mib.Text(p)))
		}
		if err == nil {
			continue
		}
		fmt.Fprintf(stderr, "atlas-portmap walk: %s: %v (after %d rows)\n", oid, err, len(pdus))
		if h := sess.Classify(err).Hint; h != "" {
			fmt.Fprintf(stderr, "  hint: %s\n", h)
		}
		status = exitFailed
		if snmpc.Fatal(err) { // no answer, credentials rejected or cancelled: the rest would fail alike
			if n := len(rest) - i - 1; n > 0 {
				fmt.Fprintf(stderr, "atlas-portmap walk: skipped the remaining %d OID(s)\n", n)
			}
			break
		}
	}
	if !*quiet {
		for _, n := range sess.Notes {
			fmt.Fprintf(stderr, "note: %s\n", n)
		}
	}
	return status
}

func cmdVendor(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: atlas-portmap vendor MAC|sysObjectID ...")
		return exitUsage
	}
	db, err := vendordb.Default()
	if err != nil {
		fmt.Fprintf(stderr, "atlas-portmap vendor: %v\n", err)
		return exitFailed
	}
	status := exitOK
	for _, a := range args {
		if m, err := macaddr.Parse(a); err == nil {
			fmt.Fprintf(stdout, "%s\t%s\n", macaddr.Format(m, "colon"), firstNonEmpty(db.MAC(m), "(unregistered)"))
			continue
		}
		if n, org := db.Enterprise(a); n >= 0 {
			fmt.Fprintf(stdout, "%s\tenterprise %d\t%s\n", mib.Norm(a), n, firstNonEmpty(org, "(unregistered)"))
			continue
		}
		fmt.Fprintf(stderr, "atlas-portmap vendor: %q is neither a MAC address nor an enterprise OID (1.3.6.1.4.1.N…)\n", a)
		status = exitUsage
	}
	return status
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
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
