package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
	"github.com/orionparker33/atlas-portmap/internal/snmptest"
)

func smallSwitch(a *snmptest.Agent) {
	pdus := []gosnmp.SnmpPDU{snmptest.Str(mib.SysName, "x"), snmptest.Str(mib.IfName+".1", "p1"), snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 1)}
	for i := 0; i < 5; i++ {
		pdus = append(pdus, snmptest.Int(mib.Dot1dTpFdbPort+"."+macIdx(i), 1))
	}
	a.Set("c", pdus...)
}

// A switch that refuses this community or user outright (SNMPv3 below the group's security
// level gets authorizationError) fails at sysName, after one request, instead of reporting an
// empty switch with a warning per table.
func TestRefusedSwitchFails(t *testing.T) {
	a := snmptest.Start(t)
	smallSwitch(a)
	a.SetFault(snmptest.Refuse(gosnmp.AuthorizationError))
	cfg := testCfg()
	cfg.Retries = 2
	sw, err := CollectSwitch(context.Background(), a.Addr, cfg, DefaultOptions())
	e := snmpc.Explain(err, cfg)
	if sw != nil || e == nil || e.Kind != snmpc.KindAccessDenied || strings.Contains(err.Error(), a.Addr) {
		t.Fatalf("sw %v err %v kind %v", sw != nil, err, e)
	}
	if a.Count(gosnmp.GetRequest) != 1 || a.Count(gosnmp.GetBulkRequest) != 0 || a.Count(gosnmp.GetNextRequest) != 0 {
		t.Errorf("requests: get %d bulk %d next %d", a.Count(gosnmp.GetRequest), a.Count(gosnmp.GetBulkRequest), a.Count(gosnmp.GetNextRequest))
	}
}

// An agent that refuses only GETBULK still maps in full over GETNEXT.
func TestBulkRefusedSwitchMaps(t *testing.T) {
	a := snmptest.Start(t)
	smallSwitch(a)
	a.SetFault(snmptest.RefuseOnly(gosnmp.AuthorizationError, gosnmp.GetBulkRequest))
	sw, err := collectWith(t, a)
	if err != nil || len(sw.FDB) != 5 || sw.Interfaces[1] == nil {
		t.Fatalf("err %v sw %+v", err, sw)
	}
}

// genErr on sysName alone is a missing object, not a refusal.
func TestSysNameGenErrStillCollects(t *testing.T) {
	a := snmptest.Start(t)
	smallSwitch(a)
	a.SetFault(func(_ string, req, reply *gosnmp.SnmpPacket) bool {
		if req.PDUType == gosnmp.GetRequest && req.Variables[0].Name == "."+mib.SysName {
			reply.Error, reply.Variables = gosnmp.GenErr, nil
		}
		return false
	})
	sw, err := collectWith(t, a)
	if err != nil || sw.SysName != "" || len(sw.FDB) != 5 || !hasWarning(sw, "sysName") {
		t.Fatalf("err %v sw %+v", err, sw)
	}
}

// A silent switch fails as no-response, without the target repeated in the error, and still
// gets the configured number of attempts.
func TestSilentSwitchFails(t *testing.T) {
	a := snmptest.Start(t)
	smallSwitch(a)
	a.SetFault(snmptest.Drop)
	cfg := testCfg()
	cfg.Retries = 1
	sw, err := CollectSwitch(context.Background(), a.Addr, cfg, DefaultOptions())
	if e := snmpc.Explain(err, cfg); sw != nil || e.Kind != snmpc.KindNoResponse || strings.Contains(err.Error(), a.Addr) || a.Count(gosnmp.GetRequest) != 2 {
		t.Fatalf("sw %v err %v kind %v, %d GETs", sw != nil, err, e, a.Count(gosnmp.GetRequest))
	}
}

// A switch that stops answering part-way keeps its table name in the error, classified.
func TestPartialSwitchErrorIsClassified(t *testing.T) {
	a := snmptest.Start(t)
	smallSwitch(a)
	a.SetFault(func(_ string, req, _ *gosnmp.SnmpPacket) bool {
		return strings.HasPrefix(req.Variables[0].Name, "."+mib.Dot1dBasePortIfIndex)
	})
	sw, err := collectWith(t, a)
	e := snmpc.Explain(err, testCfg())
	if sw == nil || e == nil || e.Kind != snmpc.KindNoResponse || !strings.HasPrefix(err.Error(), "dot1dBasePortIfIndex: ") || !strings.Contains(e.Hint, "stopped answering part-way") {
		t.Fatalf("sw %v err %v kind %+v", sw != nil, err, e)
	}
}

func TestRefusedARPSource(t *testing.T) {
	a := snmptest.Start(t)
	smallSwitch(a)
	a.SetFault(snmptest.Refuse(gosnmp.NoAccess))
	arp, err := CollectARP(context.Background(), a.Addr, testCfg())
	if e := snmpc.Explain(err, testCfg()); arp != nil || e.Kind != snmpc.KindAccessDenied || strings.Contains(err.Error(), a.Addr) {
		t.Fatalf("arp %v err %v kind %+v", arp, err, e)
	}
}
