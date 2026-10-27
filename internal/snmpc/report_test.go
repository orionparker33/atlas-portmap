package snmpc

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/snmptest"
)

const usmUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"

// reportPacket marshals a plaintext (noAuthNoPriv) SNMPv3 Report naming oid, as an agent sends
// one for discovery or to reject a request.
func reportPacket(t *testing.T, oid string) []byte {
	t.Helper()
	g := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{AuthoritativeEngineID: string(sg300), AuthoritativeEngineBoots: 3, AuthoritativeEngineTime: 497}}
	b, err := g.MkSnmpPacket(gosnmp.Report, []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Counter32, Value: uint32(1)}}, 0, 0).MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReportOID(t *testing.T) {
	if got := reportOID(reportPacket(t, ".1.3.6.1.6.3.15.1.1.5.0")); got != ".1.3.6.1.6.3.15.1.1.5.0" {
		t.Errorf("reportOID = %q", got)
	}
	g := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "c"}
	resp, _ := g.MkSnmpPacket(gosnmp.GetResponse, []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.15.1.1.5.0", Type: gosnmp.Counter32, Value: uint32(1)}}, 0, 0).MarshalMsg()
	for _, b := range [][]byte{resp, nil, []byte("not snmp at all")} {
		if got := reportOID(b); got != "" {
			t.Errorf("reportOID(%q) = %q, want none", b, got)
		}
	}
}

// v3Agent is a minimal SNMPv3 agent. It answers engine discovery with the SG300's engine ID and
// every other request with an unauthenticated Report naming report, the way agents reject a
// wrong user, key or protocol; with report "" it drops them.
type v3Agent struct {
	addr string
	mu   sync.Mutex
	reqs int // requests other than discovery
}

func startV3(t *testing.T, report string) *v3Agent {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	a := &v3Agent{addr: pc.LocalAddr().String()}
	discovery, reject := reportPacket(t, usmUnknownEngineIDs), []byte(nil)
	if report != "" {
		reject = reportPacket(t, report)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// The discovery probe is noAuthNoPriv with an empty user, so it decodes without
			// keys; an authenticated request does not.
			dec := &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.NoAuthNoPriv,
				SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "x"}}
			out := reject
			if p, err := dec.SnmpDecodePacket(append([]byte(nil), buf[:n]...)); err == nil && p.SecurityParameters.(*gosnmp.UsmSecurityParameters).UserName == "" {
				out = discovery
			} else {
				a.mu.Lock()
				a.reqs++
				a.mu.Unlock()
			}
			if out != nil {
				_, _ = pc.WriteTo(out, from)
			}
		}
	}()
	return a
}

func (a *v3Agent) requests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reqs
}

// gosnmp v1.47.0 discards these Reports as "not authentic"; the tap recovers the cause. This
// also fails if a gosnmp upgrade stops reading through Conn.Read or rewords the error.
func TestReportRecovery(t *testing.T) {
	for _, c := range []struct {
		report string
		kind   Kind
		hint   string
	}{
		{".1.3.6.1.6.3.15.1.1.3.0", KindUnknownUser, `"mapper" is not configured`},
		{".1.3.6.1.6.3.15.1.1.5.0", KindWrongDigest, "auth passphrase"},
		{".1.3.6.1.6.3.15.1.1.6.0", KindDecryption, "-v3-priv-proto des"},
	} {
		a := startV3(t, c.report)
		cfg := v3cfg("sha", "aes")
		cfg.Timeout, cfg.Retries = 300*time.Millisecond, 2
		s, err := Dial(context.Background(), a.addr, cfg, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, ok := any(s.g.Conn).(net.PacketConn)
		err = s.FirstContact(func() error { _, _, err := s.Get("1.3.6.1.2.1.1.5.0"); return err })
		e := s.Classify(err)
		s.Close()
		if ok || err == nil || !strings.Contains(err.Error(), "not authentic") {
			t.Fatalf("%s: err %v (tap is a PacketConn: %v)", c.report, err, ok)
		}
		if e.Kind != c.kind || !strings.Contains(e.Hint, c.hint) || !strings.Contains(e.Hint, "unauthenticated Report") || !Fatal(e) {
			t.Errorf("%s: kind %s hint %q", c.report, e.Kind, e.Hint)
		}
		// Rejected credentials cost one request, whatever -retries says.
		if n := a.requests(); n != 1 {
			t.Errorf("%s: the agent saw %d authenticated requests, want 1", c.report, n)
		}
	}
}

// Discovery answered, the authenticated request dropped: retried as configured, and the
// discovery Report kept from before the request must not be read as the cause.
func TestV3SilentAfterDiscovery(t *testing.T) {
	a := startV3(t, "")
	cfg := v3cfg("sha", "aes")
	cfg.Timeout, cfg.Retries = 150*time.Millisecond, 2
	s, err := Dial(context.Background(), a.addr, cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.FirstContact(func() error { _, _, err := s.Get("1.3.6.1.2.1.1.5.0"); return err })
	e := s.Classify(err)
	if e.Kind != KindV3NoResponse || !strings.Contains(e.Hint, "80:00:00:09:03:00:76:86:00:00:01, Cisco") || s.lastReport() != "" {
		t.Errorf("kind %s hint %q report %q", e.Kind, e.Hint, s.lastReport())
	}
	if n := a.requests(); n != cfg.Retries+1 {
		t.Errorf("%d authenticated requests, want %d", n, cfg.Retries+1)
	}
}

func TestClosedPort(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Go disables UDP connection-reset reporting on Windows: a closed port is a timeout there")
	}
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	s, err := Dial(context.Background(), addr, cfg(V2c), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, err = s.Get("1.3.6.1.2.1.1.5.0")
	if e := s.Classify(err); e.Kind != KindPortClosed || Fatal(err) {
		t.Errorf("err %v kind %s", err, e.Kind)
	}
}

func TestGetErrorStatus(t *testing.T) {
	a := agent(t, 5)
	s := dial(t, a, cfg(V2c))
	a.SetFault(snmptest.Refuse(gosnmp.AuthorizationError))
	_, ok, err := s.Get("1.3.6.1.2.1.1.5.0")
	var ae *AgentError
	if ok || !errors.As(err, &ae) || ae.Status != gosnmp.AuthorizationError || !IsDenied(err) || Fatal(err) {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if e := s.Classify(err); e.Kind != KindAccessDenied || err.Error() != "1.3.6.1.2.1.1.5.0: agent returned AuthorizationError" {
		t.Errorf("%q: kind %s", err, e.Kind)
	}
	a.SetFault(snmptest.Refuse(gosnmp.GenErr))
	if _, ok, err := s.Get("1.3.6.1.2.1.1.5.0"); ok || !IsAgentError(err) || IsDenied(err) {
		t.Errorf("genErr: ok %v err %v", ok, err)
	}
	a.SetFault(snmptest.Refuse(gosnmp.NoSuchName)) // v1 style "no such object", also from some v2c agents
	if _, ok, err := s.Get("1.3.6.1.2.1.1.5.0"); ok || err != nil {
		t.Errorf("noSuchName: ok %v err %v", ok, err)
	}
	a.SetFault(nil)
	if _, ok, err := s.Get("1.3.6.1.2.1.1.99.0"); ok || err != nil {
		t.Errorf("noSuchInstance: ok %v err %v", ok, err)
	}
}

// An agent that refuses everything: a walk ends in a typed AgentError, and the identical
// GETBULK and GETNEXT causes are reported once.
func TestWalkRefusedEverywhere(t *testing.T) {
	a := agent(t, 5)
	a.SetFault(snmptest.Refuse(gosnmp.AuthorizationError))
	rows, err := dial(t, a, cfg(V2c)).Walk(col)
	var ae *AgentError
	if len(rows) != 0 || !errors.As(err, &ae) || ae.Status != gosnmp.AuthorizationError || Fatal(err) || strings.Count(err.Error(), "AuthorizationError") != 1 {
		t.Errorf("rows %d err %v", len(rows), err)
	}
}

// authorizationError on GETBULK only stays non-fatal: the table is read with GETNEXT.
func TestWalkBulkRefusedFallsBack(t *testing.T) {
	a := agent(t, 40)
	a.SetFault(snmptest.RefuseOnly(gosnmp.AuthorizationError, gosnmp.GetBulkRequest))
	rows, err := dial(t, a, cfg(V2c)).Walk(col)
	if err != nil || len(rows) != 40 {
		t.Errorf("rows %d err %v", len(rows), err)
	}
}

func TestFirstContactRetries(t *testing.T) {
	c := cfg(V2c)
	c.Timeout, c.Retries = 100*time.Millisecond, 2
	// Silent: one attempt, then the remaining retries, as many requests as plain retries send.
	a := agent(t, 1)
	a.SetFault(snmptest.Drop)
	s := dial(t, a, c)
	err := s.FirstContact(func() error { _, _, err := s.Get("1.3.6.1.2.1.1.5.0"); return err })
	if s.Classify(err).Kind != KindNoResponse || a.Count(gosnmp.GetRequest) != 3 || s.g.Retries != 2 {
		t.Errorf("silent: err %v, %d requests, retries %d", err, a.Count(gosnmp.GetRequest), s.g.Retries)
	}
	// Refused: an answer, so no retry.
	b := agent(t, 1)
	b.SetFault(snmptest.Refuse(gosnmp.NoAccess))
	s = dial(t, b, c)
	err = s.FirstContact(func() error { _, _, err := s.Get("1.3.6.1.2.1.1.5.0"); return err })
	if !IsDenied(err) || b.Count(gosnmp.GetRequest) != 1 {
		t.Errorf("refused: err %v, %d requests", err, b.Count(gosnmp.GetRequest))
	}
}
