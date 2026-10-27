package snmpc

import (
	"net"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
)

// reportTap sits between gosnmp and an SNMPv3 session's socket and keeps the last datagram
// received since the last send. gosnmp v1.47.0 checks a reply's HMAC before it parses the PDU,
// so the unauthenticated Report an agent sends for a wrong user, key or protocol
// (usmStatsWrongDigests, usmStatsUnknownUserNames, …) is discarded unread and the caller gets
// only "incoming packet is not authentic". The kept datagram lets Classify name the cause.
//
// It must not implement net.PacketConn: gosnmp then reads with Read and writes with Write
// rather than ReadFrom/WriteTo on the inner socket. That holds for the connected UDP socket
// Dial asks for (Transport "udp", UseUnconnectedUDPSocket unset); TestReportRecovery fails if a
// gosnmp upgrade changes it.
type reportTap struct {
	net.Conn
	last []byte
}

// Write clears the kept datagram, so a timeout never reads a Report from an earlier request.
func (t *reportTap) Write(b []byte) (int, error) {
	t.last = t.last[:0]
	return t.Conn.Write(b)
}

func (t *reportTap) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.last = append(t.last[:0], b[:n]...)
	}
	return n, err
}

// lastReport is the usmStats OID of the Report the agent sent in place of an authenticated
// reply to the last request, or "". The Report is unauthenticated (anyone on the path could
// forge it), so it only ever explains a failure; nothing reads it as data.
func (s *Session) lastReport() string {
	if s.tap == nil || len(s.tap.last) == 0 {
		return ""
	}
	return reportOID(s.tap.last)
}

// reportOID decodes a plaintext SNMPv3 Report without checking authentication and returns
// its single varbind's OID, or "" for anything else (an authenticated or encrypted message
// does not decode without keys, and gosnmp has classified those itself).
func reportOID(datagram []byte) string {
	dec := &gosnmp.GoSNMP{
		Version:            gosnmp.Version3,
		SecurityModel:      gosnmp.UserSecurityModel,
		MsgFlags:           gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: "report"}, // required, not checked
	}
	p, err := dec.SnmpDecodePacket(append([]byte(nil), datagram...))
	if err != nil || p.PDUType != gosnmp.Report || len(p.Variables) != 1 {
		return ""
	}
	return "." + mib.Norm(p.Variables[0].Name)
}
