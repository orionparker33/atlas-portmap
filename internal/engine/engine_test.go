package engine

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/orionparker33/atlas-portmap/internal/collect"
	"github.com/orionparker33/atlas-portmap/internal/inventory"
	"github.com/orionparker33/atlas-portmap/internal/portmap"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
)

func cfg() snmpc.Config {
	return snmpc.Config{Port: 161, Version: snmpc.V2c, Community: "c", Timeout: 300 * time.Millisecond, Retries: 0, MaxRepetitions: 10}
}

func TestHosts(t *testing.T) {
	got := Hosts("10.0.0.1, 10.0.0.2\n# comment\n  core-sw.lab  edge:1161 # trailing\n\n")
	if strings.Join(got, "|") != "10.0.0.1|10.0.0.2|core-sw.lab|edge:1161" {
		t.Errorf("Hosts = %v", got)
	}
}

func TestDevices(t *testing.T) {
	inv := []inventory.Device{{Role: "switch", Host: "10.0.0.5", Alias: "closet", Version: "1", Community: "other", Line: 3}, {Role: "arp", Host: "10.0.0.1", Line: 4}}
	sw, arp, err := Devices(cfg(), []string{"10.0.0.2"}, nil, inv)
	if err != nil || len(sw) != 2 || len(arp) != 1 {
		t.Fatalf("Devices: %v %v %v", sw, arp, err)
	}
	if sw[1].Alias != "closet" || sw[1].Config.Version != snmpc.V1 || sw[1].Config.Community != "other" || arp[0].Config.Community != "c" {
		t.Errorf("overrides: %+v %+v", sw[1], arp[0])
	}
	if _, _, err := Devices(cfg(), nil, nil, []inventory.Device{{Role: "switch", Host: "x", Version: "9", Line: 7}}); err == nil || !strings.Contains(err.Error(), "line 7") {
		t.Errorf("bad version: %v", err)
	}
	if _, _, err := Devices(cfg(), []string{"10.0.0.2:0"}, nil, nil); err == nil {
		t.Error("bad target accepted")
	}
}

func TestParseVLANsAndColumns(t *testing.T) {
	got, err := ParseVLANs("30, 10-12,11,1")
	if err != nil || len(got) != 5 || got[0] != 1 || got[4] != 30 {
		t.Errorf("ParseVLANs = %v, %v", got, err)
	}
	for _, bad := range []string{"0", "4095", "x", "5-2", "1-"} {
		if _, err := ParseVLANs(bad); err == nil {
			t.Errorf("ParseVLANs(%q) accepted", bad)
		}
	}
	cols, err := ParseColumns([]string{"poe=1.3.6.1.2.1.105.1.1.1.6", "", " duplex = .1.3.6.1.2.1.10.7.2.1.19 "})
	if err != nil || len(cols) != 2 || cols[1].Name != "duplex" || cols[1].OID != "1.3.6.1.2.1.10.7.2.1.19" {
		t.Errorf("ParseColumns = %+v %v", cols, err)
	}
	for _, bad := range [][]string{{"poe"}, {"=1.3.6"}, {"a=ifAlias"}, {"a=1.3.6", "A=1.3.7"}} {
		if _, err := ParseColumns(bad); err == nil {
			t.Errorf("ParseColumns(%v) accepted", bad)
		}
	}
}

func TestPlan(t *testing.T) {
	sw := []Device{{Host: "10.0.0.2", Config: cfg()}, {Host: "10.0.0.3", Config: cfg()}}
	arp := []Device{{Host: "10.0.0.2", Config: cfg()}, {Host: "10.0.0.1", Config: cfg()}} // first duplicates a switch
	p := Plan(Request{Switches: sw, ARPSources: arp, ARPFromSwitches: true, LocalARP: true, Resolve: true})
	var got []string
	for i, e := range p {
		if e.ID != i || e.State != StateQueued {
			t.Errorf("task %d: %+v", i, e)
		}
		got = append(got, e.Role+":"+e.Target)
	}
	want := "switch:10.0.0.2|switch:10.0.0.3|arp:10.0.0.2|arp:10.0.0.1|arp:10.0.0.3|local-arp:local|dns:reverse DNS"
	if strings.Join(got, "|") != want {
		t.Errorf("plan = %v", got)
	}
}

func TestRunWithUnreachableSwitch(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := pc.LocalAddr().String()
	pc.Close()
	var mu sync.Mutex
	var events []Event
	res := Run(context.Background(), Request{
		Label: "lab", Switches: []Device{{Host: dead, Config: cfg()}}, ARPFromSwitches: true,
		Collect: collect.DefaultOptions(), Concurrency: 4,
	}, "test", func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() })
	if res.SwitchesFailed != 1 || res.Report.Label != "lab" || res.Report.Switches[0].Error == "" || len(res.Report.ARPSources) != 0 {
		t.Errorf("result: %+v / %+v", res, res.Report)
	}
	var states []string
	for _, e := range events {
		states = append(states, e.Role+"="+e.State)
	}
	if strings.Join(states, ",") != "switch=running,switch=failed,arp=skipped" {
		t.Errorf("events: %v", states)
	}
}

func TestInventoryCommunityIsNotDefaulted(t *testing.T) {
	def := snmpc.Config{Version: snmpc.V2c, Community: "public", CommunityDefaulted: true, Port: 161, Timeout: time.Second}
	sw, _, err := Devices(def, []string{"10.0.0.1"}, nil, []inventory.Device{
		{Line: 1, Role: "switch", Host: "10.0.0.9", Version: "2c", Community: "public"},
		{Line: 2, Role: "switch", Host: "10.0.0.10"},
	})
	if err != nil || len(sw) != 3 {
		t.Fatalf("%v %+v", err, sw)
	}
	for i, want := range []bool{true, false, true} {
		if sw[i].Config.CommunityDefaulted != want {
			t.Errorf("%s: CommunityDefaulted %v, want %v", sw[i].Host, sw[i].Config.CommunityDefaulted, want)
		}
	}
}

func TestRowAddrsIncludeOtherIPs(t *testing.T) {
	got := rowAddrs(portmap.Entry{IPs: []string{"10.0.0.1"}, OtherIPs: []string{"10.0.1.1 (VLAN 20)", "fe80::1 (VLAN ?)"}})
	if strings.Join(got, ",") != "10.0.0.1,10.0.1.1,fe80::1" {
		t.Errorf("%v", got)
	}
}
