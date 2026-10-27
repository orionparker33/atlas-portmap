// Package snmptest is a small in-process SNMPv1/v2c agent for tests. It serves fixed tables per
// community and can inject faults: error-status replies, empty replies, dropped requests.
package snmptest

import (
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Fault sees each request and the reply the agent would send. It may change the reply, or
// return true to drop it (the client then times out).
type Fault func(community string, req, reply *gosnmp.SnmpPacket) (drop bool)

// Drop is a Fault that drops every request, like an agent that ignores a wrong community.
func Drop(string, *gosnmp.SnmpPacket, *gosnmp.SnmpPacket) bool { return true }

// Refuse is a Fault that answers every request with error-status status, the way an agent
// refuses a community or SNMPv3 user it does not allow (authorizationError, noAccess).
func Refuse(status gosnmp.SNMPError) Fault {
	return RefuseOnly(status, gosnmp.GetRequest, gosnmp.GetNextRequest, gosnmp.GetBulkRequest)
}

// RefuseOnly answers requests of the given types with error-status status and the rest
// normally: RefuseOnly(gosnmp.AuthorizationError, gosnmp.GetBulkRequest) is an agent that
// refuses GETBULK but answers GET and GETNEXT.
func RefuseOnly(status gosnmp.SNMPError, types ...gosnmp.PDUType) Fault {
	return func(_ string, req, reply *gosnmp.SnmpPacket) bool {
		for _, t := range types {
			if req.PDUType == t {
				reply.Error, reply.ErrorIndex, reply.Variables = status, 0, nil
				for _, v := range req.Variables {
					reply.Variables = append(reply.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.Null})
				}
			}
		}
		return false
	}
}

// Agent is a running fake agent.
type Agent struct {
	Addr   string
	pc     net.PacketConn
	mu     sync.Mutex
	tables map[string][]gosnmp.SnmpPDU
	fault  Fault
	counts map[gosnmp.PDUType]int
}

var discard = gosnmp.NewLogger(log.New(io.Discard, "", 0))

// Start runs an agent on a random loopback port until the test ends.
func Start(t testing.TB) *Agent {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Addr: pc.LocalAddr().String(), pc: pc, tables: map[string][]gosnmp.SnmpPDU{}, counts: map[gosnmp.PDUType]int{}}
	go a.serve()
	t.Cleanup(func() { pc.Close() })
	return a
}

// Set replaces a community's data. A community with no data set makes the agent stay silent.
func (a *Agent) Set(community string, pdus ...gosnmp.SnmpPDU) {
	cp := make([]gosnmp.SnmpPDU, len(pdus))
	for i, p := range pdus {
		p.Name = "." + strings.TrimPrefix(p.Name, ".")
		cp[i] = p
	}
	sort.Slice(cp, func(i, j int) bool { return Less(cp[i].Name, cp[j].Name) })
	a.mu.Lock()
	a.tables[community] = cp
	a.mu.Unlock()
}

// SetFault installs a fault hook (nil removes it).
func (a *Agent) SetFault(f Fault) {
	a.mu.Lock()
	a.fault = f
	a.mu.Unlock()
}

// Count reports how many requests of a type arrived.
func (a *Agent) Count(t gosnmp.PDUType) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counts[t]
}

func (a *Agent) serve() {
	buf := make([]byte, 65535)
	dec := &gosnmp.GoSNMP{Logger: discard}
	for {
		n, from, err := a.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := dec.SnmpDecodePacket(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		reply, drop := a.handle(req)
		if drop {
			continue
		}
		if out, err := reply.MarshalMsg(); err == nil {
			_, _ = a.pc.WriteTo(out, from)
		}
	}
}

func (a *Agent) handle(req *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, bool) {
	a.mu.Lock()
	table, known := a.tables[req.Community]
	fault := a.fault
	a.counts[req.PDUType]++
	a.mu.Unlock()
	if !known {
		return nil, true // unknown community: real agents stay silent
	}
	reply := &gosnmp.SnmpPacket{Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID, Logger: discard}
	v1 := req.Version == gosnmp.Version1
	v1Error := func(i int) {
		reply.Error, reply.ErrorIndex = gosnmp.NoSuchName, uint8(i+1)
		reply.Variables = nil
		for _, v := range req.Variables {
			reply.Variables = append(reply.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.Null})
		}
	}
	switch req.PDUType {
	case gosnmp.GetRequest, gosnmp.GetNextRequest:
		for i, v := range req.Variables {
			var p gosnmp.SnmpPDU
			var ok bool
			if req.PDUType == gosnmp.GetRequest {
				p, ok = exact(table, v.Name)
			} else {
				p, ok = next(table, v.Name)
			}
			if ok {
				reply.Variables = append(reply.Variables, p)
				continue
			}
			if v1 {
				v1Error(i)
				break
			}
			typ := gosnmp.NoSuchInstance
			if req.PDUType == gosnmp.GetNextRequest {
				typ = gosnmp.EndOfMibView
			}
			reply.Variables = append(reply.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: typ})
		}
	case gosnmp.GetBulkRequest:
		cur := req.Variables[0].Name
		for i := 0; i < int(req.MaxRepetitions); i++ {
			p, ok := next(table, cur)
			if !ok {
				reply.Variables = append(reply.Variables, gosnmp.SnmpPDU{Name: cur, Type: gosnmp.EndOfMibView})
				break
			}
			reply.Variables = append(reply.Variables, p)
			cur = p.Name
		}
	default:
		return nil, true
	}
	if fault != nil && fault(req.Community, req, reply) {
		return nil, true
	}
	return reply, false
}

func exact(t []gosnmp.SnmpPDU, name string) (gosnmp.SnmpPDU, bool) {
	name = "." + strings.TrimPrefix(name, ".")
	for _, p := range t {
		if p.Name == name {
			return p, true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

func next(t []gosnmp.SnmpPDU, name string) (gosnmp.SnmpPDU, bool) {
	for _, p := range t {
		if Less(name, p.Name) {
			return p, true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

// Less orders dotted OIDs numerically.
func Less(a, b string) bool {
	x, y := strings.Split(strings.TrimPrefix(a, "."), "."), strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		p, _ := strconv.ParseUint(x[i], 10, 32)
		q, _ := strconv.ParseUint(y[i], 10, 32)
		if p != q {
			return p < q
		}
	}
	return len(x) < len(y)
}

// Int, Str, Bytes and OID build PDUs.
func Int(oid string, v int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: v}
}

// Str is an OCTET STRING PDU.
func Str(oid, v string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(v)}
}

// Bytes is an OCTET STRING PDU with raw octets.
func Bytes(oid string, v []byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: v}
}

// OID is an OBJECT IDENTIFIER PDU.
func OID(oid, v string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.ObjectIdentifier, Value: v}
}

// Column returns n rows of col with single-integer indexes 1..n and integer values.
func Column(col string, n int) []gosnmp.SnmpPDU {
	out := make([]gosnmp.SnmpPDU, n)
	for i := range out {
		out[i] = Int(col+"."+strconv.Itoa(i+1), i+1)
	}
	return out
}
