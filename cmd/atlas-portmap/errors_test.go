package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/output"
	"github.com/orionparker33/atlas-portmap/internal/snmptest"
)

func liveAgent(t *testing.T) *snmptest.Agent {
	a := snmptest.Start(t)
	a.Set("c", snmptest.Str(mib.SysName, "sw1"), snmptest.Str(mib.IfName+".1", "p1"), snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 1),
		snmptest.Int(mib.Dot1dTpFdbPort+".0.80.86.0.0.1", 1))
	return a
}

var fast = []string{"-c", "c", "-timeout", "200ms", "-retries", "0"}

func cli(args ...string) (int, string, string) {
	return runCLI(append(append([]string{}, fast...), args...)...)
}

// -q drops warnings, not failures: a failed switch is reported once, by target, with the
// classified hint and the raw cause.
func TestQuietStillReportsFailures(t *testing.T) {
	a := liveAgent(t)
	a.SetFault(snmptest.Drop)
	code, out, errb := cli("-q", a.Addr)
	want := "error: switch " + a.Addr + ": FAILED (no data) [no-response]: no answer (1 request, timeout 200ms, UDP "
	if code != exitFailed || !strings.HasPrefix(errb, want) || !strings.Contains(errb, "wrong community") ||
		!strings.Contains(errb, "\n  cause: request timeout") || strings.Count(errb, a.Addr) != 1 || strings.Count(out, "\n") != 1 {
		t.Errorf("code %d\nstdout %q\nstderr %q", code, out, errb)
	}
}

func TestDefaultCommunityIsNamed(t *testing.T) {
	t.Setenv("PORTMAP_COMMUNITY", "")
	a := liveAgent(t) // knows only "c": "public" goes unanswered
	code, _, errb := runCLI("-q", "-timeout", "200ms", "-retries", "0", a.Addr)
	if code != exitFailed || !strings.Contains(errb, `the default "public" was used`) {
		t.Errorf("code %d stderr %q", code, errb)
	}
	_, _, errb = cli("-q", "-c", "other", a.Addr)
	if strings.Contains(errb, "public") || strings.Contains(errb, "other") {
		t.Errorf("explicit community: %q", errb)
	}
}

func TestQuietCleanRun(t *testing.T) {
	a := liveAgent(t)
	code, out, errb := cli("-q", a.Addr)
	if code != exitOK || errb != "" || !strings.Contains(out, "00:50:56:00:00:01") {
		t.Errorf("code %d stderr %q\n%s", code, errb, out)
	}
}

// A refused switch (SNMPv3 below the group's level, a community without a view) fails after one
// request instead of mapping as an empty switch with a warning per table.
func TestRefusedSwitch(t *testing.T) {
	t.Setenv("PORTMAP_COMMUNITY", "c") // not -c, which warns
	a := liveAgent(t)
	a.SetFault(snmptest.Refuse(gosnmp.AuthorizationError))
	code, _, errb := runCLI("-timeout", "200ms", "-retries", "2", a.Addr)
	if code != exitFailed || !strings.Contains(errb, "[access-denied]: the agent refused the request (authorizationError)") ||
		strings.Contains(errb, "warning:") || a.Count(gosnmp.GetRequest) != 1 || a.Count(gosnmp.GetBulkRequest) != 0 {
		t.Errorf("code %d, %d GETs, %d GETBULKs, stderr %q", code, a.Count(gosnmp.GetRequest), a.Count(gosnmp.GetBulkRequest), errb)
	}
}

// One good switch, one dead, a dead ARP source: partial, every failure named, kinds in JSON.
func TestMixedRunReportsEachFailure(t *testing.T) {
	good, dead, deadARP := liveAgent(t), liveAgent(t), liveAgent(t)
	dead.SetFault(snmptest.Drop)
	deadARP.SetFault(snmptest.Drop)
	code, out, errb := cli("-q", "-o", "json", "-arp", deadARP.Addr, good.Addr, dead.Addr)
	var r output.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if code != exitPartial || len(r.Switches) != 2 || r.Switches[0].Error != "" || r.Switches[1].ErrorKind != "no-response" || r.Switches[1].Hint == "" {
		t.Fatalf("code %d switches %+v", code, r.Switches)
	}
	if !strings.Contains(errb, "error: switch "+dead.Addr+": FAILED") || !strings.Contains(errb, "error: ARP source "+deadARP.Addr+": FAILED (IP addresses from it are missing) [no-response]") {
		t.Errorf("stderr %q", errb)
	}
	for _, s := range r.ARPSources {
		if s.Target == deadARP.Addr && (s.ErrorKind != "no-response" || s.Hint == "") {
			t.Errorf("ARP source %+v", s)
		}
	}
}

func TestPartialSwitchIsCalledOut(t *testing.T) {
	a := liveAgent(t)
	a.SetFault(func(_ string, req, _ *gosnmp.SnmpPacket) bool {
		return strings.HasPrefix(req.Variables[0].Name, ".1.3.6.1.2.1.17.") // BRIDGE-MIB never answers
	})
	code, _, errb := cli("-q", "-arp-from-switches=false", a.Addr)
	if code != exitPartial || !strings.Contains(errb, "error: switch sw1 ("+a.Addr+"): PARTIAL (stopped part-way after 0 FDB rows; its rows are incomplete) [no-response]") {
		t.Errorf("code %d stderr %q", code, errb)
	}
}

// walk stops at the first fatal error rather than waiting out every OID.
func TestWalkStopsAfterFatalError(t *testing.T) {
	a := liveAgent(t)
	a.SetFault(snmptest.Drop)
	start := time.Now()
	code, _, errb := runCLI("walk", "-c", "c", "-timeout", "200ms", "-retries", "1", a.Addr, "1.3.6.1.2.1.1", "1.3.6.1.2.1.2", "1.3.6.1.2.1.17")
	if code != exitFailed || !strings.Contains(errb, "skipped the remaining 2 OID(s)") || !strings.Contains(errb, "  hint: no answer (2 requests") ||
		a.Count(gosnmp.GetBulkRequest) != 2 || a.Count(gosnmp.GetNextRequest) != 0 || time.Since(start) > 2*time.Second {
		t.Errorf("code %d after %v, %d GETBULKs, %d GETNEXTs, stderr %q", code, time.Since(start), a.Count(gosnmp.GetBulkRequest), a.Count(gosnmp.GetNextRequest), errb)
	}
}

// A refusal is not fatal to walk: the next OID may be in the view.
func TestWalkRefusedContinues(t *testing.T) {
	a := liveAgent(t)
	a.SetFault(snmptest.Refuse(gosnmp.AuthorizationError))
	code, _, errb := runCLI("walk", "-c", "c", "-timeout", "200ms", a.Addr, "1.3.6.1.2.1.1", "1.3.6.1.2.1.2")
	if code != exitFailed || strings.Count(errb, "hint: the agent refused the request (authorizationError)") != 2 || strings.Contains(errb, "skipped") {
		t.Errorf("code %d stderr %q", code, errb)
	}
}

func TestClosedPortCLI(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	code, _, errb := cli("-q", addr)
	_, port, _ := net.SplitHostPort(addr)
	// Linux and macOS see the ICMP port unreachable; Windows sees a timeout.
	if code != exitFailed || !(strings.Contains(errb, "[port-closed]: ICMP port unreachable: nothing listens on UDP "+port) || strings.Contains(errb, "[no-response]")) {
		t.Errorf("code %d stderr %q", code, errb)
	}
}
