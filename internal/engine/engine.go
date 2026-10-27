// Package engine runs one mapping job: collect from every switch and ARP source in parallel,
// join, and assemble the report. The CLI and the GUI both drive it, so they behave the same.
package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/localarp"
	"github.com/orionparker33/atlas-portmap/internal/output"
	"github.com/orionparker33/atlas-portmap/internal/portmap"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
	"github.com/orionparker33/atlas-portmap/internal/vendordb"
)

// Device is one SNMP agent to query.
type Device struct {
	Host   string
	Alias  string
	Config snmpc.Config
}

// Request is everything one mapping run needs.
type Request struct {
	Label           string // client / site the map belongs to
	Switches        []Device
	ARPSources      []Device
	ARPFromSwitches bool
	LocalARP        bool
	Collect         collect.Options
	UplinkThreshold int
	AllSightings    bool
	AllPorts        bool
	MACFormat       string
	Resolve         bool
	Concurrency     int
}

// Task roles.
const (
	RoleSwitch = "switch"
	RoleARP    = "arp"
	RoleLocal  = "local-arp"
	RoleDNS    = "dns"
)

// Task states.
const (
	StateQueued  = "queued"
	StateRunning = "running"
	StateDone    = "done"
	StateFailed  = "failed"
	StateSkipped = "skipped"
)

// Event is the state of one task. IDs are stable for a run (see Plan).
type Event struct {
	ID        int    `json:"id"`
	Role      string `json:"role"`
	Target    string `json:"target"`
	Alias     string `json:"alias,omitempty"`
	State     string `json:"state"`
	Detail    string `json:"detail,omitempty"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
}

type arpJob struct {
	id         int
	dev        Device
	fromSwitch int // index into Request.Switches, or -1 for an explicit ARP source
}

type plan struct {
	tasks    []Event
	switches []int // task ID per Request.Switches entry
	arp      []arpJob
	local    int // task ID or -1
	dns      int // task ID or -1
}

func makePlan(req Request) plan {
	p := plan{local: -1, dns: -1}
	add := func(role string, d Device) int {
		id := len(p.tasks)
		p.tasks = append(p.tasks, Event{ID: id, Role: role, Target: d.Host, Alias: d.Alias, State: StateQueued})
		return id
	}
	for _, d := range req.Switches {
		p.switches = append(p.switches, add(RoleSwitch, d))
	}
	// ARP sources: explicit routers first, then each switch; never the same agent twice.
	seen := map[string]bool{}
	key := func(d Device) string {
		c := d.Config
		return strings.Join([]string{d.Host, c.Version.String(), c.Community, c.V3User, c.V3Context}, "\x00")
	}
	for _, d := range req.ARPSources {
		if k := key(d); !seen[k] {
			seen[k] = true
			p.arp = append(p.arp, arpJob{id: add(RoleARP, d), dev: d, fromSwitch: -1})
		}
	}
	if req.ARPFromSwitches {
		for i, d := range req.Switches {
			if k := key(d); !seen[k] {
				seen[k] = true
				p.arp = append(p.arp, arpJob{id: add(RoleARP, d), dev: d, fromSwitch: i})
			}
		}
	}
	if req.LocalARP {
		p.local = add(RoleLocal, Device{Host: localarp.Source})
	}
	if req.Resolve {
		p.dns = add(RoleDNS, Device{Host: "reverse DNS"})
	}
	return p
}

// Plan lists the tasks Run will perform, all queued, in the order Run reports them.
func Plan(req Request) []Event { return makePlan(req).tasks }

// Result is a finished run.
type Result struct {
	Report          *output.Report
	SwitchesFailed  int  // switches that returned nothing
	SwitchesPartial int  // switches that returned data and then stopped answering
	ARPFailed       int  // ARP sources (including the local cache) that failed
	Interrupted     bool // the run was cancelled or hit its deadline
}

// Complete reports a run in which every device answered in full.
func (r Result) Complete() bool {
	return r.SwitchesFailed == 0 && r.SwitchesPartial == 0 && r.ARPFailed == 0 && !r.Interrupted
}

// Run performs the job. onEvent, if not nil, receives every task update; calls are serialised.
func Run(ctx context.Context, req Request, version string, onEvent func(Event)) Result {
	p := makePlan(req)
	var mu sync.Mutex
	emit := func(e Event) {
		if onEvent != nil {
			mu.Lock()
			onEvent(e)
			mu.Unlock()
		}
	}
	start := func(id int) time.Time {
		e := p.tasks[id]
		e.State = StateRunning
		emit(e)
		return time.Now()
	}
	finish := func(id int, t0 time.Time, detail string, err error) {
		e := p.tasks[id]
		e.ElapsedMS, e.Detail, e.State = time.Since(t0).Milliseconds(), detail, StateDone
		if err != nil {
			e.State, e.Error = StateFailed, err.Error()
		}
		emit(e)
	}
	conc := max(req.Concurrency, 1)

	// Explicit ARP sources run alongside the switches; a switch's own ARP table is read right
	// after the switch, by the same worker, so a slow switch never holds up anyone else's.
	sws := make([]*collect.Switch, len(req.Switches))
	swErrs := make([]error, len(req.Switches))
	arpRes := make([][]collect.ARPEntry, len(p.arp))
	arpErrs := make([]error, len(p.arp))
	skipped := make([]bool, len(p.arp))
	arpOf := map[int]int{}
	for i, j := range p.arp {
		if j.fromSwitch >= 0 {
			arpOf[j.fromSwitch] = i
		}
	}
	readARP := func(i int) {
		j := p.arp[i]
		t0 := start(j.id)
		arpRes[i], arpErrs[i] = collect.CollectARP(ctx, j.dev.Host, j.dev.Config)
		finish(j.id, t0, fmt.Sprintf("%d entries", len(arpRes[i])), arpErrs[i])
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	work := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn()
		}()
	}
	for i, j := range p.arp {
		if j.fromSwitch < 0 {
			work(func() { readARP(i) })
		}
	}
	for i := range req.Switches {
		work(func() {
			id, d := p.switches[i], req.Switches[i]
			t0 := start(id)
			sws[i], swErrs[i] = collect.CollectSwitch(ctx, d.Host, d.Config, req.Collect)
			detail := ""
			if sws[i] != nil {
				sws[i].Alias = d.Alias
				detail = fmt.Sprintf("%d FDB rows, %d interfaces", len(sws[i].FDB), len(sws[i].Interfaces))
			}
			finish(id, t0, detail, swErrs[i])
			ai, ok := arpOf[i]
			if !ok {
				return
			}
			if sws[i] == nil { // already failed as a switch
				e := p.tasks[p.arp[ai].id]
				e.State, e.Detail = StateSkipped, "the switch failed"
				emit(e)
				skipped[ai] = true
				return
			}
			readARP(ai)
		})
	}
	wg.Wait()

	report := &output.Report{Tool: "atlas-portmap", Version: version, Label: req.Label, Generated: time.Now().UTC().Format(time.RFC3339)}
	res := Result{Report: report}
	var arp []collect.ARPEntry
	for i, j := range p.arp {
		if skipped[i] {
			continue
		}
		s := output.SourceSummary{Target: j.dev.Host, Entries: len(arpRes[i])}
		if arpErrs[i] != nil {
			s.Error = arpErrs[i].Error()
			s.ErrorKind, s.Hint = explain(arpErrs[i], j.dev.Config)
			res.ARPFailed++
		}
		report.ARPSources = append(report.ARPSources, s)
		arp = append(arp, arpRes[i]...)
	}
	if p.local >= 0 {
		t0 := start(p.local)
		la, err := localarp.Read(ctx)
		s := output.SourceSummary{Target: localarp.Source, Entries: len(la)}
		if err != nil {
			s.Error = err.Error()
			s.ErrorKind, s.Hint = explain(err, snmpc.Config{})
			res.ARPFailed++
		}
		report.ARPSources = append(report.ARPSources, s)
		arp = append(arp, la...)
		finish(p.local, t0, fmt.Sprintf("%d entries", len(la)), err)
	}

	db, dbErr := vendordb.Default()
	vendorOf := func(net.HardwareAddr) string { return "" }
	if dbErr == nil {
		vendorOf = db.MAC
	} else {
		report.Warnings = append(report.Warnings, "vendor database unavailable: "+dbErr.Error())
	}
	for i, d := range req.Switches {
		sum := output.SwitchSummary{Target: d.Host}
		if sw := sws[i]; sw != nil {
			sum.Name, sum.Description, sum.SysObjectID = sw.Name(), sw.SysDescr, sw.SysObjectID
			sum.FDBSource, sum.FDBRows, sum.LLDP, sum.Warnings = sw.FDBSource, len(sw.FDB), sw.LLDPSeen, sw.Warnings
			if dbErr == nil {
				if n, org := db.Enterprise(sw.SysObjectID); n >= 0 {
					sum.Vendor = org
				}
			}
		}
		if swErrs[i] != nil {
			sum.Error = swErrs[i].Error()
			sum.ErrorKind, sum.Hint = explain(swErrs[i], d.Config)
			if sws[i] == nil {
				res.SwitchesFailed++
			} else {
				sum.Partial = true
				res.SwitchesPartial++
			}
		}
		report.Switches = append(report.Switches, sum)
	}
	opt := portmap.Options{
		UplinkThreshold: req.UplinkThreshold, AllSightings: req.AllSightings, AllPorts: req.AllPorts,
		Vendor: vendorOf, MACFormat: req.MACFormat,
	}
	if p.local >= 0 {
		opt.LocalMACs = localarp.OwnMACs()
	}
	report.Entries = portmap.Build(sws, arp, opt)
	if p.dns >= 0 {
		t0 := start(p.dns)
		n := ResolveNames(ctx, report.Entries, conc*2)
		finish(p.dns, t0, fmt.Sprintf("%d names", n), ctx.Err())
	}
	if ctx.Err() != nil {
		res.Interrupted = true
		report.Warnings = append(report.Warnings, "run interrupted before it finished ("+ctx.Err().Error()+"); the map is incomplete")
	}
	return res
}

// explain gives a failure's kind and hint for the report.
func explain(err error, c snmpc.Config) (string, string) {
	e := snmpc.Explain(err, c)
	return string(e.Kind), e.Hint
}

// ResolveNames fills Hostnames by reverse DNS, at most workers lookups at a time, and returns
// how many addresses resolved.
func ResolveNames(ctx context.Context, entries []portmap.Entry, workers int) int {
	ips := map[string][]string{}
	for _, e := range entries {
		for _, ip := range rowAddrs(e) {
			ips[ip] = nil
		}
	}
	keys := make([]string, 0, len(ips))
	for k := range ips {
		keys = append(keys, k)
	}
	names := make([][]string, len(keys))
	parallel(workers, len(keys), func(i int) {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		got, err := net.DefaultResolver.LookupAddr(c, keys[i])
		if err != nil {
			return
		}
		for _, n := range got {
			names[i] = append(names[i], strings.TrimSuffix(n, "."))
		}
		sort.Strings(names[i])
	})
	resolved := 0
	for i, k := range keys {
		ips[k] = names[i]
		if len(names[i]) > 0 {
			resolved++
		}
	}
	for i := range entries {
		var hn []string
		seen := map[string]bool{}
		for _, ip := range rowAddrs(entries[i]) {
			for _, n := range ips[ip] {
				if !seen[n] {
					seen[n] = true
					hn = append(hn, n)
				}
			}
		}
		entries[i].Hostnames = hn
	}
	return resolved
}

// rowAddrs is a row's addresses, its own first, then those in other_ips ("ip (VLAN n|?)"), so a
// router on a trunk keeps its name on every VLAN row.
func rowAddrs(e portmap.Entry) []string {
	out := append([]string(nil), e.IPs...)
	for _, o := range e.OtherIPs {
		ip, _, _ := strings.Cut(o, " (")
		out = append(out, ip)
	}
	return out
}

func parallel(limit, n int, fn func(int)) {
	sem := make(chan struct{}, max(limit, 1))
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(i)
		}()
	}
	wg.Wait()
}
