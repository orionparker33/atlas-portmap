package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/snmpc"
	"github.com/orionparker33/atlas-portmap/internal/snmptest"
)

func testCfg() snmpc.Config {
	return snmpc.Config{Version: snmpc.V2c, Community: "c", Timeout: 250 * time.Millisecond, Retries: 0, MaxRepetitions: 10}
}

func macIdx(i int) string { return fmt.Sprintf("0.80.86.0.%d.%d", i/256, i%256) }

func ciscoBase(vlans ...int) []gosnmp.SnmpPDU {
	p := []gosnmp.SnmpPDU{
		snmptest.Str(mib.SysName, "cat"), snmptest.OID(mib.SysObjectID, ".1.3.6.1.4.1.9.1.1208"),
		snmptest.Str(mib.IfName+".10101", "Gi1/0/1"), snmptest.Int(mib.IfType+".10101", 6),
		snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 10101),
	}
	for i := 0; i < 5; i++ {
		p = append(p, snmptest.Int(mib.Dot1dTpFdbPort+"."+macIdx(i), 1), snmptest.Int(mib.Dot1dTpFdbStatus+"."+macIdx(i), 3))
	}
	for _, v := range vlans {
		p = append(p, snmptest.Int(fmt.Sprintf("%s.1.%d", mib.VtpVlanState, v), 1), snmptest.Int(fmt.Sprintf("%s.1.%d", mib.VtpVlanType, v), 1))
	}
	return p
}

func collectWith(t *testing.T, a *snmptest.Agent) (*Switch, error) {
	t.Helper()
	return CollectSwitch(context.Background(), a.Addr, testCfg(), DefaultOptions())
}

func hasWarning(sw *Switch, sub string) bool {
	for _, w := range sw.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestPerVLANAuthorizationErrorIsReported(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", ciscoBase(1, 10, 20)...)
	for _, v := range []int{1, 10, 20} {
		a.Set(fmt.Sprintf("c@%d", v), snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 10101))
	}
	a.SetFault(func(comm string, _, reply *gosnmp.SnmpPacket) bool {
		if strings.Contains(comm, "@") {
			reply.Error, reply.Variables = gosnmp.AuthorizationError, nil
		}
		return false
	})
	sw, err := collectWith(t, a)
	if err != nil || sw.FDBSource != "bridge" || len(sw.FDB) != 5 || !hasWarning(sw, "not readable for VLAN 1,10,20") {
		t.Fatalf("err %v source %q fdb %d warnings %v", err, sw.FDBSource, len(sw.FDB), sw.Warnings)
	}
}

func TestPerVLANEmptyInstancesAreReported(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", ciscoBase(1, 10, 20)...)
	for _, v := range []int{1, 10, 20} {
		a.Set(fmt.Sprintf("c@%d", v)) // answers, but the view holds nothing
	}
	sw, err := collectWith(t, a)
	if err != nil || len(sw.FDB) != 5 || !hasWarning(sw, "returned nothing") {
		t.Fatalf("err %v fdb %d warnings %v", err, len(sw.FDB), sw.Warnings)
	}
}

func TestPerVLANCircuitBreaker(t *testing.T) {
	a := snmptest.Start(t)
	vlans := make([]int, 40)
	for i := range vlans {
		vlans[i] = i + 1
	}
	a.Set("c", ciscoBase(vlans...)...) // no c@N data: the agent stays silent for every VLAN
	start := time.Now()
	sw, err := collectWith(t, a)
	if err != nil || !hasWarning(sw, "stopped after 4 timeouts") || time.Since(start) > 4*time.Second {
		t.Fatalf("err %v, %v, warnings %v", err, time.Since(start), sw.Warnings)
	}
}

func TestCiscoWithoutVTPWarns(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", ciscoBase()...)
	sw, err := collectWith(t, a)
	if err != nil || !hasWarning(sw, "without readable CISCO-VTP-MIB") {
		t.Fatalf("err %v warnings %v", err, sw.Warnings)
	}
}

func TestJuniperVLANTags(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c",
		snmptest.Str(mib.SysName, "ex"), snmptest.OID(mib.SysObjectID, ".1.3.6.1.4.1.2636.1.1.1.2.29"),
		snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 501),
		snmptest.Int(mib.Dot1qTpFdbPort+".17."+macIdx(1), 1), snmptest.Int(mib.Dot1qTpFdbStatus+".17."+macIdx(1), 3),
		snmptest.Int(mib.Dot1qVlanFdbId+".0.17", 17), snmptest.Str(mib.Dot1qVlanStaticName+".17", "voice"),
		snmptest.Int(mib.Dot1qPvid+".1", 17),
		snmptest.Int(mib.JnxL2aldVlanTag+".17", 156), snmptest.Int(mib.JnxL2aldVlanFdbID+".17", 17),
	)
	sw, err := collectWith(t, a)
	if err != nil || len(sw.FDB) != 1 || sw.FDB[0].VLAN != 156 || sw.VLANNames[156] != "voice" || sw.PVID[1] != 156 {
		t.Fatalf("err %v fdb %+v names %v pvid %v", err, sw.FDB, sw.VLANNames, sw.PVID)
	}
}

func TestFDBIDsOutsideVLANRange(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", snmptest.Str(mib.SysName, "x"),
		snmptest.Int(mib.Dot1qTpFdbPort+".5000."+macIdx(1), 1), snmptest.Int(mib.Dot1qTpFdbStatus+".5000."+macIdx(1), 3))
	sw, err := collectWith(t, a)
	if err != nil || len(sw.FDB) != 1 || sw.FDB[0].VLAN != 0 || !hasWarning(sw, "not VLAN IDs") {
		t.Fatalf("err %v fdb %+v warnings %v", err, sw.FDB, sw.Warnings)
	}
}

func TestInterfaceStack(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", snmptest.Str(mib.SysName, "x"),
		snmptest.Int(mib.IfStackStatus+".100.47", 1), snmptest.Int(mib.IfStackStatus+".100.48", 1),
		snmptest.Int(mib.IfStackStatus+".0.100", 1), snmptest.Int(mib.IfStackStatus+".47.0", 1),
		snmptest.Int(mib.Dot3adAggPortAttachedAggID+".47", 100), snmptest.Int(mib.Dot3adAggPortAttachedAggID+".49", 0))
	sw, err := collectWith(t, a)
	if err != nil || fmt.Sprint(sw.Stack[47]) != "[100]" || fmt.Sprint(sw.Stack[48]) != "[100]" || len(sw.Stack) != 2 {
		t.Fatalf("err %v stack %v", err, sw.Stack)
	}
}

func TestPartialTableIsKeptWithWarning(t *testing.T) {
	a := snmptest.Start(t)
	pdus := []gosnmp.SnmpPDU{snmptest.Str(mib.SysName, "x"), snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 1)}
	for i := 0; i < 60; i++ {
		pdus = append(pdus, snmptest.Int(mib.Dot1dTpFdbPort+"."+macIdx(i), 1))
	}
	a.Set("c", pdus...)
	bulk, next := 0, 0
	a.SetFault(func(_ string, req, reply *gosnmp.SnmpPacket) bool {
		if !strings.HasPrefix(req.Variables[0].Name, "."+mib.Dot1dTpFdbPort) {
			return false
		}
		switch req.PDUType {
		case gosnmp.GetBulkRequest:
			if bulk++; bulk > 1 {
				reply.Error, reply.Variables = gosnmp.GenErr, nil
			}
		case gosnmp.GetNextRequest:
			if next++; next > 25 {
				reply.Error, reply.Variables = gosnmp.GenErr, nil
			}
		}
		return false
	})
	sw, err := collectWith(t, a)
	if err != nil || len(sw.FDB) != 25 || !hasWarning(sw, "dot1dTpFdbPort: incomplete (25 rows)") {
		t.Fatalf("err %v fdb %d warnings %v", err, len(sw.FDB), sw.Warnings)
	}
}

func TestSwitchThatStopsAnsweringIsPartial(t *testing.T) {
	a := snmptest.Start(t)
	a.Set("c", snmptest.Str(mib.SysName, "x"), snmptest.Str(mib.IfName+".1", "p1"), snmptest.Int(mib.Dot1dBasePortIfIndex+".1", 1))
	a.SetFault(func(_ string, req, _ *gosnmp.SnmpPacket) bool {
		return strings.HasPrefix(req.Variables[0].Name, ".1.3.6.1.2.1.17.") // BRIDGE-MIB never answers
	})
	sw, err := collectWith(t, a)
	if sw == nil || err == nil || !snmpc.Fatal(err) || sw.Interfaces[1] == nil {
		t.Fatalf("sw %v err %v", sw != nil, err)
	}
}
