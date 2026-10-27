//go:build e2e

// Package e2e runs the built atlas-portmap binary against snmpsim serving a synthetic network:
// a Q-BRIDGE core switch, a BRIDGE-MIB access switch cascaded below it, a Cisco switch with
// per-VLAN BRIDGE-MIB instances, and a router holding the ARP table. Run it via scripts/e2e.sh,
// which provides SNMPSIM (the snmpsim-command-responder path).
package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
	"github.com/orionparker33/atlas-portmap/internal/output"
	"github.com/orionparker33/atlas-portmap/internal/portmap"
)

const (
	mA, mB, mC, mD, mE = "00:50:56:00:00:0a", "b8:27:eb:00:00:0b", "00:00:0c:00:00:0c", "00:15:5d:00:00:0d", "00:00:0c:00:00:0e"
	mCore, mAcc        = "00:00:0c:cc:cc:cc", "00:00:0c:aa:aa:aa"
	mVM1, mVM2         = "02:00:00:00:00:01", "02:00:00:00:00:02"
	mG1, mG2, mF1      = "00:1b:63:00:01:01", "3c:22:fb:00:02:02", "00:00:0c:00:0f:01"

	v3User, v3Auth, v3Priv = "mapper", "authpass-e2e-123", "privpass-e2e-456"
)

type rec struct {
	oid      []uint32
	tag, val string
}

type device struct{ recs []rec }

func (d *device) add(oid, tag, val string) {
	v, err := mib.Ints(mib.Norm(oid))
	if err != nil {
		panic(err)
	}
	d.recs = append(d.recs, rec{v, tag, val})
}
func (d *device) str(oid, s string)        { d.add(oid, "4", s) }
func (d *device) raw(oid string, b []byte) { d.add(oid, "4x", hex.EncodeToString(b)) }
func (d *device) num(oid string, n int)    { d.add(oid, "2", strconv.Itoa(n)) }
func (d *device) gauge(oid string, n int)  { d.add(oid, "66", strconv.Itoa(n)) }
func (d *device) objid(oid, v string)      { d.add(oid, "6", v) }

func (d *device) write(t *testing.T, path string) {
	sort.Slice(d.recs, func(i, j int) bool { return less(d.recs[i].oid, d.recs[j].oid) })
	var b strings.Builder
	for _, r := range d.recs {
		parts := make([]string, len(r.oid))
		for i, x := range r.oid {
			parts[i] = strconv.FormatUint(uint64(x), 10)
		}
		fmt.Fprintf(&b, "%s|%s|%s\n", strings.Join(parts, "."), r.tag, r.val)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func less(a, b []uint32) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func macBytes(s string) []byte {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func macIdx(s string) string {
	var p []string
	for _, b := range macBytes(s) {
		p = append(p, strconv.Itoa(int(b)))
	}
	return strings.Join(p, ".")
}

func at(col string, idx ...any) string {
	s := col
	for _, i := range idx {
		s += "." + fmt.Sprint(i)
	}
	return s
}

func (d *device) system(descr, objectID, name, base string) {
	d.str(mib.SysDescr, descr)
	d.objid(mib.SysObjectID, objectID)
	d.str(mib.SysName, name)
	if base != "" {
		d.raw(mib.Dot1dBaseBridgeAddress, macBytes(base))
	}
}

func (d *device) iface(idx int, name, alias string, typ, oper int) {
	d.str(at(mib.IfDescr, idx), name)
	d.num(at(mib.IfType, idx), typ)
	d.num(at(mib.IfAdminStatus, idx), 1)
	d.num(at(mib.IfOperStatus, idx), oper)
	d.str(at(mib.IfName, idx), name)
	d.gauge(at(mib.IfHighSpeed, idx), 1000)
	if alias != "" {
		d.str(at(mib.IfAlias, idx), alias)
	}
}

func (d *device) lldpRem(localPort int, chassis, port, sysName string, caps byte) {
	idx := fmt.Sprintf("0.%d.1", localPort)
	d.num(at(mib.LldpRemChassisIdSubtype, idx), 4)
	d.raw(at(mib.LldpRemChassisId, idx), macBytes(chassis))
	d.num(at(mib.LldpRemPortIdSubtype, idx), 5)
	d.str(at(mib.LldpRemPortId, idx), port)
	d.str(at(mib.LldpRemSysName, idx), sysName)
	d.raw(at(mib.LldpRemSysCapEnabled, idx), []byte{caps, 0})
}

func writeTopology(t *testing.T, dir string) {
	// core: Q-BRIDGE switch (HP/Aruba sysObjectID), L3 with its own ARP table.
	core := &device{}
	core.system("Aruba 2930F", "1.3.6.1.4.1.11.2.3.7.11.181", "core", mCore)
	core.iface(1, "Gi1/0/1", "srv-01", 6, 1)
	core.iface(2, "Gi1/0/2", "to-access", 6, 1)
	core.iface(3, "Gi1/0/3", "", 6, 2)
	core.iface(4, "Gi1/0/4", "vm-host", 6, 1)
	core.iface(100, "Vlan10", "", 53, 1)
	for bp := 1; bp <= 4; bp++ {
		core.num(at(mib.Dot1dBasePortIfIndex, bp), bp)
		core.num(at(mib.LldpLocPortIdSubtype, bp), 5)
		core.str(at(mib.LldpLocPortId, bp), fmt.Sprintf("Gi1/0/%d", bp))
	}
	for bp, pvid := range map[int]int{1: 10, 2: 1, 3: 1, 4: 30} {
		core.num(at(mib.Dot1qPvid, bp), pvid)
	}
	for vid, name := range map[int]string{1: "default", 10: "users", 20: "voice", 30: "vms"} {
		core.str(at(mib.Dot1qVlanStaticName, vid), name)
		core.gauge(at(mib.Dot1qVlanFdbId, 0, vid), vid)
	}
	for _, f := range []struct {
		fid    int
		mac    string
		bp, st int
	}{{10, mA, 1, 3}, {20, mB, 2, 3}, {20, mC, 2, 3}, {20, mD, 2, 3}, {1, mAcc, 2, 3}, {30, mVM1, 4, 3}, {30, mVM2, 4, 3}, {1, mCore, 1, 4}} {
		core.num(at(mib.Dot1qTpFdbPort, f.fid, macIdx(f.mac)), f.bp)
		core.num(at(mib.Dot1qTpFdbStatus, f.fid, macIdx(f.mac)), f.st)
	}
	core.lldpRem(2, mAcc, "ge-0/0/24", "access.lab.example", 0x20)
	core.raw(at(mib.IpNetToMediaPhysAddress, 100, "10.0.10.5"), macBytes(mA))
	core.num(at(mib.IpNetToMediaType, 100, "10.0.10.5"), 3)
	core.write(t, filepath.Join(dir, "core.snmprec"))

	// access: BRIDGE-MIB only (no Q-BRIDGE FDB), VLAN from PVID; LLDP local ports numbered by
	// ifIndex in lldpLocPortId (subtype local).
	acc := &device{}
	acc.system("Juniper EX2300", "1.3.6.1.4.1.2636.1.1.1.2.29", "access", mAcc)
	for _, p := range []struct{ idx, bp, oper, pvid int }{{101, 1, 1, 20}, {102, 2, 1, 20}, {124, 24, 1, 1}, {125, 25, 2, 1}} {
		acc.iface(p.idx, fmt.Sprintf("ge-0/0/%d", p.bp), "", 6, p.oper)
		acc.num(at(mib.Dot1dBasePortIfIndex, p.bp), p.idx)
		acc.num(at(mib.Dot1qPvid, p.bp), p.pvid)
		acc.num(at(mib.LldpLocPortIdSubtype, p.bp), 7)
		acc.str(at(mib.LldpLocPortId, p.bp), strconv.Itoa(p.idx))
	}
	for _, f := range []struct {
		mac string
		bp  int
	}{{mB, 1}, {mC, 2}, {mD, 2}, {mA, 24}, {mCore, 24}, {mE, 99}} {
		acc.num(at(mib.Dot1dTpFdbPort, macIdx(f.mac)), f.bp)
		acc.num(at(mib.Dot1dTpFdbStatus, macIdx(f.mac)), 3)
	}
	acc.lldpRem(2, mC, "Port 1", "SEP0000C000000C", 0x24) // phone: telephone + bridge
	acc.lldpRem(24, mCore, "Gi1/0/2", "core", 0x28)
	acc.write(t, filepath.Join(dir, "access.snmprec"))

	// cisco: VTP VLANs 1, 10, 20 (1002 FDDI default ignored), per-VLAN instances for 10 and 20
	// only, so VLAN 1's instance is missing and the default instance must be kept.
	cs := &device{}
	cs.system("Cisco IOS Software, Catalyst L3 Switch", "1.3.6.1.4.1.9.1.2066", "cat9300", "")
	cs.iface(10101, "Gi1/0/1", "", 6, 1)
	cs.iface(10105, "Gi1/0/5", "", 6, 1)
	cs.iface(10148, "Gi1/0/48", "", 6, 1)
	cs.num(at(mib.Dot1dBasePortIfIndex, 48), 10148)
	cs.num(at(mib.Dot1dTpFdbPort, macIdx(mF1)), 48)
	cs.num(at(mib.Dot1dTpFdbStatus, macIdx(mF1)), 3)
	for vid, typ := range map[int]int{1: 1, 10: 1, 20: 1, 1002: 2} {
		cs.num(at(mib.VtpVlanState, 1, vid), 1)
		cs.num(at(mib.VtpVlanType, 1, vid), typ)
	}
	cs.str(at(mib.CdpCacheDeviceId, 10148, 1), "core.lab.example")
	cs.str(at(mib.CdpCacheDevicePort, 10148, 1), "1/1/48")
	cs.str(at(mib.CdpCachePlatform, 10148, 1), "Aruba JL322A 2930F")
	cs.raw(at(mib.CdpCacheCapabilities, 10148, 1), []byte{0, 0, 0, 0x09})
	cs.write(t, filepath.Join(dir, "cisco.snmprec"))
	for vid, row := range map[int]struct {
		bp, ifx int
		mac     string
	}{10: {1, 10101, mG1}, 20: {5, 10105, mG2}} {
		v := &device{}
		v.num(at(mib.Dot1dBasePortIfIndex, row.bp), row.ifx)
		v.num(at(mib.Dot1dTpFdbPort, macIdx(row.mac)), row.bp)
		v.num(at(mib.Dot1dTpFdbStatus, macIdx(row.mac)), 3)
		v.write(t, filepath.Join(dir, fmt.Sprintf("cisco@%d.snmprec", vid)))
	}

	// router: ipNetToPhysicalTable (IPv4 + IPv6) including one invalid row.
	rt := &device{}
	rt.system("edge router", "1.3.6.1.4.1.8072.3.2.10", "edge-rtr", "")
	v6 := "254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1"
	for _, a := range []struct {
		idx, mac string
		typ      int
	}{
		{"2.1.4.10.0.20.6", mB, 3}, {"2.2.16." + v6, mB, 3}, {"2.1.4.10.0.20.8", mD, 3},
		{"2.1.4.10.0.20.99", "00:11:22:33:44:99", 2}, {"3.1.4.10.0.1.50", mG1, 3}, {"3.1.4.10.0.2.60", mG2, 3},
	} {
		rt.raw(at(mib.IpNetToPhysicalPhysAddress, a.idx), macBytes(a.mac))
		rt.num(at(mib.IpNetToPhysicalType, a.idx), a.typ)
	}
	rt.write(t, filepath.Join(dir, "router.snmprec"))

	// sg300: a real Cisco SG300-10 (firmware 1.4.11.2, L2 mode) captured with walk on 2026-10-27
	// and anonymized by tools/walk2snmprec (OUIs kept, NIC bytes replaced).
	b, err := os.ReadFile(filepath.Join("testdata", "sg300-10.snmprec"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sg300.snmprec"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type harness struct {
	bin, target string
}

func setup(t *testing.T) *harness {
	sim := os.Getenv("SNMPSIM")
	if sim == "" {
		t.Skip("SNMPSIM not set (path to snmpsim-command-responder); run scripts/e2e.sh")
	}
	dir := t.TempDir()
	data, cache := filepath.Join(dir, "data"), filepath.Join(dir, "cache")
	for _, d := range []string{data, cache} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTopology(t, data)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	target := fmt.Sprintf("127.0.0.1:%d", port)

	var simLog bytes.Buffer
	cmd := exec.Command(sim, "--data-dir="+data, "--cache-dir="+cache, "--agent-udpv4-endpoint="+target,
		"--v3-user="+v3User, "--v3-auth-key="+v3Auth, "--v3-auth-proto=SHA", "--v3-priv-key="+v3Priv, "--v3-priv-proto=AES",
		"--logging-method=stderr", "--log-level=error")
	cmd.Stdout, cmd.Stderr = &simLog, &simLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("snmpsim log:\n%s", simLog.String())
		}
	})
	g := &gosnmp.GoSNMP{Target: "127.0.0.1", Port: uint16(port), Community: "core", Version: gosnmp.Version2c, Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(45 * time.Second)
	for {
		if err := g.Connect(); err == nil {
			r, err := g.Get([]string{mib.SysName})
			g.Conn.Close()
			if err == nil && len(r.Variables) == 1 && r.Variables[0].Type == gosnmp.OctetString {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("snmpsim did not answer on %s:\n%s", target, simLog.String())
		}
		time.Sleep(300 * time.Millisecond)
	}

	bin := filepath.Join(dir, "atlas-portmap")
	build := exec.Command("go", "build", "-race", "-o", bin, "../cmd/atlas-portmap")
	if os.Getenv("E2E_NO_RACE") != "" {
		build = exec.Command("go", "build", "-o", bin, "../cmd/atlas-portmap")
	}
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return &harness{bin: bin, target: target}
}

func (h *harness) run(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errb.String()
}

func entriesByMAC(r *output.Report) map[string][]portmap.Entry {
	m := map[string][]portmap.Entry{}
	for _, e := range r.Entries {
		m[e.MAC] = append(m[e.MAC], e)
	}
	return m
}

func TestEndToEnd(t *testing.T) {
	h := setup(t)
	inv := filepath.Join(t.TempDir(), "devices.csv")
	csv := fmt.Sprintf("# e2e lab\nswitch,%[1]s,,2c,core\nswitch,%[1]s,,2c,access\nswitch,%[1]s,closet-cisco,2c,cisco\narp,%[1]s,edge-rtr,2c,router\n", h.target)
	if err := os.WriteFile(inv, []byte(csv), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("map v2c", func(t *testing.T) {
		code, out, errb := h.run(t, nil, "map", "-inventory", inv, "-o", "json", "-timeout", "1s", "-retries", "0", "-all-ports")
		if code != 0 {
			t.Fatalf("exit %d\nstderr:\n%s", code, errb)
		}
		var r output.Report
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("json: %v\n%s", err, out)
		}
		got := entriesByMAC(&r)
		want := map[string]struct {
			sw, port string
			vlan     int
			ips      string
			uplink   bool
		}{
			mA:    {"core", "Gi1/0/1", 10, "10.0.10.5", false},
			mB:    {"access", "ge-0/0/1", 20, "10.0.20.6,fe80::1", false},
			mC:    {"access", "ge-0/0/2", 20, "", false},
			mD:    {"access", "ge-0/0/2", 20, "10.0.20.8", false},
			mE:    {"access", "bridge port 99", 0, "", false},
			mAcc:  {"core", "Gi1/0/2", 1, "", true},
			mCore: {"access", "ge-0/0/24", 1, "", true},
			mVM1:  {"core", "Gi1/0/4", 30, "", false},
			mVM2:  {"core", "Gi1/0/4", 30, "", false},
			mG1:   {"closet-cisco", "Gi1/0/1", 10, "10.0.1.50", false},
			mG2:   {"closet-cisco", "Gi1/0/5", 20, "10.0.2.60", false},
			mF1:   {"closet-cisco", "Gi1/0/48", 0, "", true}, // default instance kept; CDP neighbour is core
		}
		for m, w := range want {
			rows := got[m]
			if len(rows) != 1 {
				t.Errorf("%s: %d rows %+v", m, len(rows), rows)
				continue
			}
			e := rows[0]
			if e.Switch != w.sw || e.Port != w.port || e.VLAN != w.vlan || strings.Join(e.IPs, ",") != w.ips || e.Uplink != w.uplink {
				t.Errorf("%s: got %s %s vlan %d ips %v uplink %v (%s); want %+v", m, e.Switch, e.Port, e.VLAN, e.IPs, e.Uplink, e.UplinkReason, w)
			}
		}
		if e := got[mA][0]; e.Vendor != "VMware, Inc." || e.VLANName != "users" || e.PortAlias != "srv-01" || e.SpeedMbps != 1000 {
			t.Errorf("A details: %+v", e)
		}
		if e := got[mVM1][0]; e.Vendor != "(locally administered)" {
			t.Errorf("VM vendor %q", e.Vendor)
		}
		if e := got[mF1][0]; e.UplinkReason != "faces core" || !strings.Contains(e.Neighbor, "cdp core.lab.example") {
			t.Errorf("F1 uplink via CDP: %+v", e)
		}
		if e := got[mC][0]; !strings.Contains(e.Neighbor, "SEP0000C000000C") || !strings.Contains(e.Neighbor, "phone") {
			t.Errorf("phone neighbour: %+v", e)
		}
		for _, bad := range []string{"00:11:22:33:44:99"} {
			for _, e := range r.Entries {
				if strings.Join(e.IPs, ",") == "10.0.20.99" || e.MAC == bad {
					t.Errorf("invalid ARP row leaked: %+v", e)
				}
			}
		}
		empty := map[string]bool{}
		for _, e := range got[""] {
			empty[e.Switch+" "+e.Port] = true
		}
		for _, want := range []string{"core Gi1/0/3", "access ge-0/0/25", "closet-cisco Gi1/0/1"} {
			_ = want
		}
		if !empty["core Gi1/0/3"] || !empty["access ge-0/0/25"] || empty["core Vlan10"] {
			t.Errorf("all-ports rows: %v", empty)
		}
		sw := map[string]output.SwitchSummary{}
		for _, s := range r.Switches {
			sw[s.Name] = s
		}
		if s := sw["core"]; s.FDBSource != "q-bridge" || !s.LLDP || !strings.Contains(s.Vendor, "Hewlett") {
			t.Errorf("core summary: %+v", s)
		}
		if s := sw["access"]; s.FDBSource != "bridge" || !s.LLDP || !strings.Contains(s.Vendor, "Juniper") {
			t.Errorf("access summary: %+v", s)
		}
		if s := sw["closet-cisco"]; s.FDBSource != "cisco-per-vlan" || s.LLDP || s.Vendor == "" {
			t.Errorf("cisco summary: %+v", s)
		}
		if e := got[mB][0]; e.VLANSource != "fdb-other-switch" || got[mA][0].VLANSource != "fdb" {
			t.Errorf("VLAN sources: B %q, A %q", e.VLANSource, got[mA][0].VLANSource)
		}
		if !strings.Contains(errb, "per-VLAN BRIDGE-MIB not readable for VLAN 1 ") {
			t.Errorf("missing per-VLAN warning for the absent cisco@1 instance; stderr:\n%s", errb)
		}
		for _, e := range r.Entries {
			if r.Switches[e.SwitchIndex].Target != e.SwitchAddr {
				t.Errorf("switch_index %d does not match %s", e.SwitchIndex, e.SwitchAddr)
				break
			}
		}
		if !strings.Contains(errb, "LLDP not exposed") {
			t.Errorf("expected the LLDP warning for the Cisco switch; stderr:\n%s", errb)
		}
		var routerSeen bool
		for _, s := range r.ARPSources {
			if s.Entries == 5 && s.Error == "" {
				routerSeen = true
			}
		}
		if !routerSeen {
			t.Errorf("router ARP source: %+v", r.ARPSources)
		}
	})

	t.Run("table and csv", func(t *testing.T) {
		for _, f := range []string{"table", "csv"} {
			code, out, errb := h.run(t, nil, "-inventory", inv, "-o", f, "-timeout", "1s", "-retries", "0", "-q")
			if code != 0 || !strings.Contains(out, "ge-0/0/1") || errb != "" {
				t.Errorf("%s: exit %d stderr %q\n%s", f, code, errb, out)
			}
			if os.Getenv("E2E_SHOW") != "" {
				t.Logf("%s output:\n%s", f, out)
			}
		}
	})

	t.Run("v3 authPriv with context", func(t *testing.T) {
		env := []string{"PORTMAP_V3_USER=" + v3User, "PORTMAP_V3_AUTH_PASS=" + v3Auth, "PORTMAP_V3_PRIV_PASS=" + v3Priv}
		code, out, errb := h.run(t, env, "-v", "3", "-v3-auth-proto", "sha", "-v3-priv-proto", "aes", "-v3-context", "core",
			"-o", "json", "-timeout", "2s", "-retries", "0", h.target)
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, errb)
		}
		if strings.Contains(out+errb, v3Auth) || strings.Contains(out+errb, v3Priv) {
			t.Error("SNMPv3 secret in output")
		}
		var r output.Report
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		if e := entriesByMAC(&r)[mA]; len(e) != 1 || e[0].Port != "Gi1/0/1" || e[0].VLAN != 10 {
			t.Errorf("v3 A: %+v", e)
		}
	})

	t.Run("v3 wrong passphrase fails fast", func(t *testing.T) {
		env := []string{"PORTMAP_V3_USER=" + v3User, "PORTMAP_V3_AUTH_PASS=wrong-pass-0000", "PORTMAP_V3_PRIV_PASS=" + v3Priv}
		start := time.Now()
		code, _, errb := h.run(t, env, "-v", "3", "-v3-context", "core", "-timeout", "1s", "-retries", "0", h.target)
		if code != 1 || strings.Contains(errb, "wrong-pass-0000") {
			t.Errorf("exit %d stderr %q", code, errb)
		}
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("took %v", d)
		}
	})

	t.Run("unreachable switch", func(t *testing.T) {
		pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
		dead := pc.LocalAddr().String()
		pc.Close()
		code, _, errb := h.run(t, nil, "-c", "core", "-timeout", "500ms", "-retries", "0", "-q", dead)
		if code != 1 {
			t.Errorf("exit %d, want 1; stderr %q", code, errb)
		}
		code, _, _ = h.run(t, nil, "-c", "core", "-timeout", "500ms", "-retries", "0", "-q", "-o", "json", h.target, dead)
		if code != 3 {
			t.Errorf("partial: exit %d, want 3", code)
		}
	})

	t.Run("gui api", func(t *testing.T) { guiAPI(t, h, csv) })

	t.Run("walk", func(t *testing.T) {
		code, out, errb := h.run(t, []string{"PORTMAP_COMMUNITY=access"}, "walk", h.target, mib.SysName, "1.3.6.1.2.1.17.1.4.1.2")
		if code != 0 || !strings.Contains(out, "1.3.6.1.2.1.1.5.0 = STRING: access") || !strings.Contains(out, "1.3.6.1.2.1.17.1.4.1.2.24 = INTEGER: 124") {
			t.Errorf("walk exit %d stderr %q\n%s", code, errb, out)
		}
	})

	t.Run("real SG300-10", func(t *testing.T) { realSG300(t, h) })
}

// realSG300 maps the recorded SG300-10: physical ports gi1-gi10 are ifIndex 49-58, Po1-8 are
// 1000-1007 (unused), VLAN interfaces are named just "1", "50", "60", the switch's own MAC sits
// in the FDB on VLAN 1 at bridge port 0, and its one ARP entry hangs off ifIndex 300000 ("50").
// gi10 is the trunk to the firewall: tagged 50 and 60, PVID 1.
func realSG300(t *testing.T, h *harness) {
	const (
		pve, hub, pi, fw, self = "a0:36:9f:c6:4f:ac", "bc:24:11:73:f5:b7", "88:a2:9e:c8:5f:06", "00:15:17:d2:c0:04", "00:76:86:09:0b:dc"
	)
	code, out, errb := h.run(t, []string{"PORTMAP_COMMUNITY=sg300"}, "map", "-o", "json", "-timeout", "1s", "-retries", "0", "-all-ports", h.target)
	if code != 0 {
		t.Fatalf("exit %d\nstderr:\n%s", code, errb)
	}
	var r output.Report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if len(r.Switches) != 1 {
		t.Fatalf("switches: %+v", r.Switches)
	}
	if s := r.Switches[0]; s.Name != "switch090bdc" || s.FDBSource != "q-bridge" || s.FDBRows != 5 || !s.LLDP || s.Error != "" {
		t.Errorf("summary: %+v", s)
	}
	got := entriesByMAC(&r)
	type row struct {
		port string
		vlan int
		ips  string
	}
	for mac, want := range map[string][]row{
		pve: {{"gi1", 50, ""}},
		hub: {{"gi1", 50, "192.168.50.10"}}, // from the switch's own ARP table
		pi:  {{"gi3", 50, ""}},
		fw:  {{"gi10", 50, ""}, {"gi10", 60, ""}}, // router-on-a-stick: one MAC on two VLANs
	} {
		var have []row
		for _, e := range got[mac] {
			have = append(have, row{e.Port, e.VLAN, strings.Join(e.IPs, ",")})
		}
		sort.Slice(have, func(i, j int) bool { return have[i].vlan < have[j].vlan })
		if fmt.Sprint(have) != fmt.Sprint(want) {
			t.Errorf("%s: got %v, want %v", mac, have, want)
		}
	}
	if len(got[self]) != 0 {
		t.Errorf("the switch's own MAC was mapped: %+v", got[self])
	}
	var empty []string
	for _, e := range got[""] {
		empty = append(empty, fmt.Sprintf("%s:%d/%s/%s/%s", e.Port, e.VLAN, e.VLANSource, e.PortMode, e.PortStatus))
	}
	// Empty ports show the VLAN they are configured for (dot1qVlanCurrentUntaggedPorts).
	if w := "gi2:60/port/access/down,gi4:50/port/access/down,gi5:50/port/access/down,gi6:50/port/access/down," +
		"gi7:50/port/access/down,gi8:50/port/access/down,gi9:60/port/access/up"; strings.Join(empty, ",") != w {
		t.Errorf("empty ports\n got %v\nwant %s\n(Po, tunnel, loopback and VLAN interfaces must not be listed)", empty, w)
	}
	ports := map[string]bool{}
	for _, e := range r.Entries {
		ports[e.Port] = true
		if e.Port == "gi1" && e.MACsOnPort != 2 {
			t.Errorf("gi1 macs_on_port %d", e.MACsOnPort)
		}
		if e.MemberOf != "" {
			t.Errorf("%s: member_of %q (Po1-8 are unused)", e.Port, e.MemberOf)
		}
		if e.Port == "gi10" && (e.PortMode != "trunk" || e.NativeVLAN != 1 || e.TaggedVLANs != "50,60" || e.PortStatus != "up") {
			t.Errorf("gi10 trunk: mode %q native %d tagged %q status %q", e.PortMode, e.NativeVLAN, e.TaggedVLANs, e.PortStatus)
		}
		if (e.Port == "gi1" || e.Port == "gi3") && (e.PortMode != "access" || e.NativeVLAN != 0 || e.PortStatus != "up") {
			t.Errorf("%s: mode %q native %d status %q", e.Port, e.PortMode, e.NativeVLAN, e.PortStatus)
		}
	}
	if len(ports) != 10 {
		t.Errorf("ports %v, want gi1-gi10", ports)
	}
	code, out, _ = h.run(t, []string{"PORTMAP_COMMUNITY=sg300"}, "map", "-timeout", "1s", "-retries", "0", h.target)
	if code != 0 || !strings.Contains(out, "trunk: tagged 50,60; native 1") {
		t.Errorf("table output exit %d:\n%s", code, out)
	}
}

// guiAPI starts "atlas-portmap gui", runs a scan through its HTTP API against snmpsim, checks the
// result and the security guard on the real listener, then quits it from the API.
func guiAPI(t *testing.T, h *harness, inventoryCSV string) {
	cmd := exec.Command(h.bin, "gui", "-no-browser")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	exited := false
	defer func() {
		if !exited {
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	line := make([]byte, 512)
	n, _ := stdout.Read(line)
	go func() { _, _ = io.Copy(io.Discard, stdout); done <- cmd.Wait() }()
	m := regexp.MustCompile(`http://(127\.0\.0\.1:\d+)/#token=([0-9a-f]{64})`).FindStringSubmatch(string(line[:n]))
	if m == nil {
		t.Fatalf("no URL in %q (stderr %q)", line[:n], errb.String())
	}
	base, token := "http://"+m[1], m[2]
	client := &http.Client{Timeout: 10 * time.Second}
	req := func(method, path, body string, hdr map[string]string) (*http.Response, []byte) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r, _ := http.NewRequest(method, base+path, rd)
		r.Header.Set("X-Portmap-Token", token)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			if k == "Host" {
				r.Host = v
			} else {
				r.Header.Set(k, v)
			}
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	if resp, _ := req("GET", "/api/meta", "", map[string]string{"Host": "rebind.attacker.test:" + strings.Split(m[1], ":")[1]}); resp.StatusCode != 403 {
		t.Errorf("DNS-rebinding Host accepted: %d", resp.StatusCode)
	}
	if resp, _ := req("GET", "/", "", nil); resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("index: %d", resp.StatusCode)
	}
	payload, _ := json.Marshal(map[string]any{
		"label": "e2e lab", "inventory": inventoryCSV,
		"snmp":    map[string]any{"version": "2c", "timeout_ms": 1000, "retries": 0},
		"options": map[string]any{"lldp": true, "cdp": true, "arp_from_switches": true, "all_ports": true, "uplink_threshold": 10},
	})
	resp, b := req("POST", "/api/scans", string(payload), map[string]string{"Origin": base})
	if resp.StatusCode != 202 {
		t.Fatalf("start scan: %d %s", resp.StatusCode, b)
	}
	var job struct {
		ID, State string
		Report    *output.Report
		Total     int
	}
	_ = json.Unmarshal(b, &job)
	deadline := time.Now().Add(90 * time.Second)
	for job.State == "running" {
		if time.Now().After(deadline) {
			t.Fatal("scan did not finish")
		}
		time.Sleep(300 * time.Millisecond)
		_, b = req("GET", "/api/scans/"+job.ID, "", nil)
		_ = json.Unmarshal(b, &job)
	}
	if job.State != "done" || job.Report == nil || job.Report.Label != "e2e lab" {
		t.Fatalf("scan result: state %s", job.State)
	}
	got := entriesByMAC(job.Report)
	for mac, port := range map[string]string{mA: "core Gi1/0/1", mB: "access ge-0/0/1", mG2: "closet-cisco Gi1/0/5"} {
		if e := got[mac]; len(e) != 1 || e[0].Switch+" "+e[0].Port != port {
			t.Errorf("%s via GUI: %+v", mac, e)
		}
	}
	resp, b = req("GET", "/api/scans/"+job.ID+"/export?format=csv", "", nil)
	if resp.StatusCode != 200 || !strings.HasPrefix(string(b), "switch,switch_addr,port") || !strings.Contains(resp.Header.Get("Content-Disposition"), "e2e-lab-") {
		t.Errorf("export: %d %q", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	if resp, _ := req("POST", "/api/quit", "", nil); resp.StatusCode != 200 {
		t.Errorf("quit: %d", resp.StatusCode)
	}
	select {
	case err := <-done:
		exited = true
		if err != nil {
			t.Errorf("gui exit: %v (stderr %q)", err, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Error("gui did not exit after quit")
	}
}
