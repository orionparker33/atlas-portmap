package snmpc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/snmptest"
)

const col = "1.3.6.1.2.1.17.4.3.1.2"

func cfg(v Version) Config {
	return Config{Version: v, Community: "public", Timeout: 300 * time.Millisecond, Retries: 0, MaxRepetitions: 10}
}

func agent(t *testing.T, rows int) *snmptest.Agent {
	a := snmptest.Start(t)
	a.Set("public", append(snmptest.Column(col, rows), snmptest.Str("1.3.6.1.2.1.1.5.0", "sw"), snmptest.Int("1.3.6.1.2.1.17.4.3.1.3.1", 3))...)
	return a
}

func dial(t *testing.T, a *snmptest.Agent, c Config) *Session {
	s, err := Dial(context.Background(), a.Addr, c, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestWalkPlain(t *testing.T) {
	a := agent(t, 100)
	for _, v := range []Version{V1, V2c} {
		rows, err := dial(t, a, cfg(v)).Walk(col)
		if err != nil || len(rows) != 100 || !strings.HasSuffix(rows[99].Name, ".100") {
			t.Errorf("v%s: %d rows, %v", v, len(rows), err)
		}
	}
}

// An agent that answers a later GETBULK with genErr must not truncate the table silently.
func TestWalkErrorStatusFallsBackToGETNEXT(t *testing.T) {
	a := agent(t, 100)
	bulks := 0
	a.SetFault(func(_ string, req, reply *gosnmp.SnmpPacket) bool {
		if req.PDUType == gosnmp.GetBulkRequest {
			if bulks++; bulks > 1 {
				reply.Error, reply.Variables = gosnmp.GenErr, nil
			}
		}
		return false
	})
	rows, err := dial(t, a, cfg(V2c)).Walk(col)
	if err != nil || len(rows) != 100 {
		t.Fatalf("got %d rows, %v; want 100 via GETNEXT", len(rows), err)
	}
}

func TestWalkErrorEverywhereReturnsPartialAndError(t *testing.T) {
	a := agent(t, 100)
	bulks, nexts := 0, 0
	a.SetFault(func(_ string, req, reply *gosnmp.SnmpPacket) bool {
		switch req.PDUType {
		case gosnmp.GetBulkRequest:
			if bulks++; bulks > 1 {
				reply.Error, reply.Variables = gosnmp.AuthorizationError, nil
			}
		case gosnmp.GetNextRequest:
			if nexts++; nexts > 15 {
				reply.Error, reply.Variables = gosnmp.GenErr, nil
			}
		}
		return false
	})
	rows, err := dial(t, a, cfg(V2c)).Walk(col)
	if err == nil || len(rows) != 15 || Fatal(err) {
		t.Fatalf("got %d rows, err %v (fatal %v); want the 15 GETNEXT rows and a non-fatal error", len(rows), err, Fatal(err))
	}
}

// tooBig with an empty varbind list (RFC 3416) halves max-repetitions.
func TestWalkTooBigHalves(t *testing.T) {
	a := agent(t, 60)
	a.SetFault(func(_ string, req, reply *gosnmp.SnmpPacket) bool {
		if req.PDUType == gosnmp.GetBulkRequest && req.MaxRepetitions > 3 {
			reply.Error, reply.Variables = gosnmp.TooBig, nil
		}
		return false
	})
	rows, err := dial(t, a, cfg(V2c)).Walk(col)
	if err != nil || len(rows) != 60 || a.Count(gosnmp.GetNextRequest) != 0 {
		t.Fatalf("got %d rows, %v, %d GETNEXTs", len(rows), err, a.Count(gosnmp.GetNextRequest))
	}
}

// An agent that answers GET/GETNEXT but ignores GETBULK is read with GETNEXT, once it has
// answered something, and the session stays on GETNEXT.
func TestWalkUnansweredBulkDowngrades(t *testing.T) {
	a := agent(t, 30)
	a.SetFault(func(_ string, req, _ *gosnmp.SnmpPacket) bool { return req.PDUType == gosnmp.GetBulkRequest })
	s := dial(t, a, cfg(V2c))
	if _, ok, err := s.Get("1.3.6.1.2.1.1.5.0"); !ok || err != nil {
		t.Fatalf("get: %v %v", ok, err)
	}
	rows, err := s.Walk(col)
	if err != nil || len(rows) != 30 || len(s.Notes) != 1 {
		t.Fatalf("got %d rows, %v, notes %v", len(rows), err, s.Notes)
	}
	before := a.Count(gosnmp.GetBulkRequest)
	if rows, err := s.Walk(col); err != nil || len(rows) != 30 || a.Count(gosnmp.GetBulkRequest) != before {
		t.Errorf("second walk: %d rows, %v, bulk requests %d -> %d", len(rows), err, before, a.Count(gosnmp.GetBulkRequest))
	}
}

func TestWalkSilentAgentIsFatalWithoutFallback(t *testing.T) {
	a := agent(t, 5)
	a.SetFault(func(string, *gosnmp.SnmpPacket, *gosnmp.SnmpPacket) bool { return true })
	start := time.Now()
	_, err := dial(t, a, cfg(V2c)).Walk(col)
	if !Fatal(err) || a.Count(gosnmp.GetNextRequest) != 0 || time.Since(start) > 2*time.Second {
		t.Errorf("err %v, %d GETNEXTs, %v", err, a.Count(gosnmp.GetNextRequest), time.Since(start))
	}
}

func TestCancelUnblocksRequest(t *testing.T) {
	a := agent(t, 5)
	a.SetFault(func(string, *gosnmp.SnmpPacket, *gosnmp.SnmpPacket) bool { return true })
	ctx, cancel := context.WithCancel(context.Background())
	c := cfg(V2c)
	c.Timeout, c.Retries = 10*time.Second, 2
	s, err := Dial(ctx, a.Addr, c, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	_, _, err = s.Get("1.3.6.1.2.1.1.5.0")
	if !errors.Is(err, context.Canceled) || time.Since(start) > 2*time.Second {
		t.Errorf("err %v after %v", err, time.Since(start))
	}
}

func TestOIDLess(t *testing.T) {
	if !OIDLess("1.3.6.1.2", "1.3.6.1.10") || OIDLess("1.3.6.1.10", "1.3.6.1.2") || !OIDLess(".1.3", "1.3.1") || OIDLess("1.3", "1.3") {
		t.Error("OIDLess")
	}
}
