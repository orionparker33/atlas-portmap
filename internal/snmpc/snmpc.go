// Package snmpc wraps gosnmp sessions: SNMPv1/v2c/v3 configuration, per-VLAN instances, and
// table walks that fall back from GETBULK to GETNEXT.
package snmpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
)

// Version is the SNMP protocol version.
type Version int

// SNMP versions.
const (
	V1  Version = 1
	V2c Version = 2
	V3  Version = 3
)

// ParseVersion accepts 1, v1, 2, 2c, v2c, 3, v3.
func ParseVersion(s string) (Version, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "v1":
		return V1, nil
	case "2", "2c", "v2", "v2c":
		return V2c, nil
	case "3", "v3":
		return V3, nil
	}
	return 0, fmt.Errorf("unknown SNMP version %q (1, 2c or 3)", s)
}

func (v Version) String() string {
	switch v {
	case V1:
		return "1"
	case V2c:
		return "2c"
	case V3:
		return "3"
	}
	return "?"
}

// Config holds connection settings. Secrets (Community, V3AuthPass, V3PrivPass) never appear
// in errors, hints or String output.
type Config struct {
	Port           uint16
	Version        Version
	Community      string
	V3User         string
	V3AuthProto    string // none, md5, sha, sha224, sha256, sha384, sha512
	V3AuthPass     string
	V3PrivProto    string // none, des, aes, aes192, aes256, aes192c, aes256c
	V3PrivPass     string
	V3Context      string // SNMPv3 context for the default instance (per-VLAN uses vlan-N)
	Timeout        time.Duration
	Retries        int
	MaxRepetitions uint32

	// CommunityDefaulted marks Community as the implicit "public" (none was given), so a
	// no-response hint can say so.
	CommunityDefaulted bool
}

func authProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToLower(s) {
	case "", "none", "noauth":
		return gosnmp.NoAuth, nil
	case "md5":
		return gosnmp.MD5, nil
	case "sha", "sha1":
		return gosnmp.SHA, nil
	case "sha224":
		return gosnmp.SHA224, nil
	case "sha256":
		return gosnmp.SHA256, nil
	case "sha384":
		return gosnmp.SHA384, nil
	case "sha512":
		return gosnmp.SHA512, nil
	}
	return 0, fmt.Errorf("unknown SNMPv3 auth protocol %q", s)
}

func privProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToLower(s) {
	case "", "none", "nopriv":
		return gosnmp.NoPriv, nil
	case "des":
		return gosnmp.DES, nil
	case "aes", "aes128":
		return gosnmp.AES, nil
	case "aes192":
		return gosnmp.AES192, nil
	case "aes256":
		return gosnmp.AES256, nil
	case "aes192c":
		return gosnmp.AES192C, nil
	case "aes256c":
		return gosnmp.AES256C, nil
	}
	return 0, fmt.Errorf("unknown SNMPv3 privacy protocol %q", s)
}

// Validate checks the configuration without contacting anything.
func (c Config) Validate() error {
	if c.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if c.Retries < 0 {
		return errors.New("retries must not be negative")
	}
	switch c.Version {
	case V1, V2c:
		if c.Community == "" {
			return errors.New("SNMPv1/v2c needs a community")
		}
	case V3:
		if c.V3User == "" {
			return errors.New("SNMPv3 needs a user (-v3-user or PORTMAP_V3_USER)")
		}
		ap, err := authProto(c.V3AuthProto)
		if err != nil {
			return err
		}
		pp, err := privProto(c.V3PrivProto)
		if err != nil {
			return err
		}
		if ap == gosnmp.NoAuth && pp != gosnmp.NoPriv {
			return errors.New("SNMPv3 privacy requires authentication")
		}
		if ap != gosnmp.NoAuth && len(c.V3AuthPass) < 8 {
			return errors.New("SNMPv3 auth passphrase must be at least 8 characters (PORTMAP_V3_AUTH_PASS)")
		}
		if pp != gosnmp.NoPriv && len(c.V3PrivPass) < 8 {
			return errors.New("SNMPv3 privacy passphrase must be at least 8 characters (PORTMAP_V3_PRIV_PASS), or -v3-priv-proto none for a user without privacy")
		}
	default:
		return fmt.Errorf("unsupported SNMP version %d", c.Version)
	}
	return nil
}

// SplitTarget splits "host", "host:port", "[v6]:port" or a bare IPv6 literal.
func SplitTarget(target string, defPort uint16) (string, uint16, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", 0, errors.New("empty target")
	}
	if strings.HasPrefix(t, "[") || strings.Count(t, ":") == 1 {
		host, ps, err := net.SplitHostPort(t)
		if err != nil {
			return "", 0, fmt.Errorf("bad target %q: %w", target, err)
		}
		p, err := strconv.ParseUint(ps, 10, 16)
		if err != nil || p == 0 {
			return "", 0, fmt.Errorf("bad port in target %q", target)
		}
		return host, uint16(p), nil
	}
	return t, defPort, nil
}

// Session is one SNMP agent connection. It is not safe for concurrent use.
type Session struct {
	g        *gosnmp.GoSNMP
	ctx      context.Context
	cfg      Config     // for Classify's hints (secrets never reach them)
	tap      *reportTap // SNMPv3 only
	stop     func() bool
	answered bool // the agent has answered at least one request
	noBulk   bool // GETBULK went unanswered on a live agent: use GETNEXT from now on
	Target   string
	Notes    []string // one-off observations for the caller to report (e.g. the GETNEXT downgrade)
}

// Dial opens a session to target. vlan > 0 selects a Cisco per-VLAN BRIDGE-MIB instance:
// community "<community>@<vlan>" for v1/v2c, context "vlan-<vlan>" for v3. Cancelling ctx
// closes the socket, so a request blocked on a silent agent returns at once.
func Dial(ctx context.Context, target string, c Config, vlan int) (*Session, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	host, port, err := SplitTarget(target, c.Port)
	if err != nil {
		return nil, err
	}
	g := &gosnmp.GoSNMP{
		Target:         host,
		Port:           port,
		Transport:      "udp",
		Context:        ctx,
		Timeout:        c.Timeout,
		Retries:        c.Retries,
		MaxOids:        gosnmp.MaxOids,
		MaxRepetitions: c.MaxRepetitions,
	}
	switch c.Version {
	case V1, V2c:
		g.Version = gosnmp.Version2c
		if c.Version == V1 {
			g.Version = gosnmp.Version1
		}
		g.Community = c.Community
		if vlan > 0 {
			g.Community = fmt.Sprintf("%s@%d", c.Community, vlan)
		}
	case V3:
		ap, _ := authProto(c.V3AuthProto)
		pp, _ := privProto(c.V3PrivProto)
		flags := gosnmp.NoAuthNoPriv
		if ap != gosnmp.NoAuth {
			flags = gosnmp.AuthNoPriv
			if pp != gosnmp.NoPriv {
				flags = gosnmp.AuthPriv
			}
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = flags
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 c.V3User,
			AuthenticationProtocol:   ap,
			AuthenticationPassphrase: c.V3AuthPass,
			PrivacyProtocol:          pp,
			PrivacyPassphrase:        c.V3PrivPass,
		}
		g.ContextName = c.V3Context
		if vlan > 0 {
			g.ContextName = fmt.Sprintf("vlan-%d", vlan)
		}
	}
	if err := g.Connect(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err() // the run itself was cancelled or hit -deadline
		}
		// Connect resolves a host name under the -timeout dial deadline before any SNMP request
		// is sent: say so, rather than blaming the community or the agent.
		var de *net.DNSError
		if errors.As(err, &de) {
			h := fmt.Sprintf("could not resolve host name %q: use an IP address, or check the DNS resolver", host)
			if de.IsTimeout {
				h = fmt.Sprintf("DNS lookup of %q timed out before any SNMP request was sent: use an IP address, or check the DNS resolver", host)
			}
			return nil, &Error{Kind: KindOther, Hint: h, Err: err}
		}
		return nil, err // the caller knows the target
	}
	s := &Session{g: g, ctx: ctx, cfg: c, Target: target}
	if c.Version == V3 {
		s.tap = &reportTap{Conn: g.Conn}
		g.Conn = s.tap
	}
	s.stop = context.AfterFunc(ctx, func() {
		if g.Conn != nil {
			_ = g.Conn.Close()
		}
	})
	return s, nil
}

// Close releases the socket.
func (s *Session) Close() {
	if s == nil || s.g == nil {
		return
	}
	if s.stop != nil {
		s.stop()
	}
	if s.g.Conn != nil {
		_ = s.g.Conn.Close()
	}
}

// RemoteIP is the address the session talks to (a resolved hostname), or "".
func (s *Session) RemoteIP() string {
	if s == nil || s.g == nil || s.g.Conn == nil {
		return ""
	}
	if a, ok := s.g.Conn.RemoteAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// cancelled returns the context error once the run has been cancelled, so callers see a
// cancellation rather than the closed-socket error it causes.
func (s *Session) cancelled(err error) error {
	if s.ctx != nil && s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	return err
}

// Get fetches one scalar. ok is false when the agent has no such object: noSuchObject,
// noSuchInstance, or error-status noSuchName (SNMPv1's way, which some v2c agents use too). Any
// other error-status is an *AgentError. SNMPv1 agents report a refusal as noSuchName too
// (RFC 3584), so on v1 a refusal still reads as absent.
func (s *Session) Get(oid string) (gosnmp.SnmpPDU, bool, error) {
	r, err := s.g.Get([]string{oid})
	if err != nil {
		return gosnmp.SnmpPDU{}, false, s.cancelled(err)
	}
	if r.PDUType == gosnmp.Report {
		return gosnmp.SnmpPDU{}, false, reportErr(r)
	}
	s.answered = true
	switch {
	case r.Error == gosnmp.NoSuchName:
		return gosnmp.SnmpPDU{}, false, nil
	case r.Error != gosnmp.NoError:
		return gosnmp.SnmpPDU{}, false, &AgentError{OID: mib.Norm(oid), Status: r.Error, get: true}
	case len(r.Variables) == 0 || mib.Missing(r.Variables[0]):
		return gosnmp.SnmpPDU{}, false, nil
	}
	return r.Variables[0], true, nil
}

// reportErr: gosnmp v1.47.0 re-synchronises once on an authenticated usmStatsNotInTimeWindows
// or usmStatsUnknownEngineIDs Report and retransmits; when the retransmit draws the same Report
// it returns that Report as the reply. Its varbind is a usmStats counter, never the object asked
// for, so it is an error, not data.
func reportErr(p *gosnmp.SnmpPacket) error {
	oid := ""
	if len(p.Variables) > 0 {
		oid = mib.Norm(p.Variables[0].Name)
	}
	switch oid {
	case "1.3.6.1.6.3.15.1.1.2.0":
		return fmt.Errorf("%w (agent Report %s)", gosnmp.ErrNotInTimeWindow, oid)
	case "1.3.6.1.6.3.15.1.1.4.0":
		return fmt.Errorf("%w (agent Report %s)", gosnmp.ErrUnknownEngineID, oid)
	}
	return fmt.Errorf("%w (agent Report %s)", gosnmp.ErrUnknownReportPDU, oid)
}

// FirstContact runs fn, the session's first request, with no retries, and again with the
// remaining retries only if nothing answered: the attempts and the time to give up on a silent
// agent stay as configured, but wrong credentials cost one attempt instead of retries+1. Each
// rejected attempt counts as an authentication failure on the agent and can raise an
// authenticationFailure trap at the client's NOC.
func (s *Session) FirstContact(fn func() error) error {
	retries := s.g.Retries
	s.g.Retries = 0
	err := fn()
	s.g.Retries = retries
	if err == nil || retries == 0 || s.answered || !s.Classify(err).Kind.NoResponse() {
		return err
	}
	s.g.Retries = retries - 1
	defer func() { s.g.Retries = retries }()
	if err = fn(); err != nil && !s.answered && s.ctx.Err() == nil && s.Classify(err).Kind.NoResponse() {
		err = fmt.Errorf("%w (%d requests in all)", err, retries+1) // gosnmp counts only this call's retries
	}
	return err
}

// Classify explains err, an error from this session, with what the session learned: the
// SNMPv3 engine ID from discovery, whether the agent has answered before, and the Report the
// agent sent in place of an authenticated reply. A *Error is returned as it is.
func (s *Session) Classify(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		return e
	}
	var engineID []byte
	if usp, ok := s.g.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		engineID = []byte(usp.AuthoritativeEngineID)
	}
	report := ""
	if notAuthentic(err) {
		report = s.lastReport()
	}
	c := s.cfg
	c.Port = s.g.Port // a target's own :port wins over -port
	return classify(err, c, engineID, report, s.answered)
}

// maxRows bounds a single table walk (a misbehaving agent must not loop forever).
const maxRows = 2_000_000

// Walk returns every instance beneath root.
//
// v2c/v3 use GETBULK. An error-status reply (genErr, noAccess, authorizationError, …) or a
// non-increasing OID makes it retry the table with GETNEXT; tooBig halves max-repetitions first.
// If GETBULK goes unanswered on an agent that has answered before, the session switches to
// GETNEXT for good and records a Note. SNMPv1 uses GETNEXT. An absent subtree is an empty
// result. When rows were read before a failure, they are returned together with the error, so
// the caller can keep them and warn.
func (s *Session) Walk(root string) ([]gosnmp.SnmpPDU, error) {
	if s.g.Version == gosnmp.Version1 || s.noBulk {
		return s.walk(root, false)
	}
	bulkRows, err := s.walk(root, true)
	if err == nil {
		return bulkRows, nil
	}
	if Fatal(err) {
		if !s.answered || !IsTimeout(err) || s.ctx.Err() != nil {
			return bulkRows, err
		}
		s.noBulk = true
		s.Notes = append(s.Notes, "GETBULK went unanswered; switched to GETNEXT for this device")
	}
	rows, err2 := s.walk(root, false)
	if err2 != nil {
		if len(bulkRows) > len(rows) {
			rows = bulkRows
		}
		if err.Error() == err2.Error() {
			return rows, fmt.Errorf("getbulk and getnext: %w", err2)
		}
		return rows, fmt.Errorf("getbulk: %v; getnext: %w", err, err2)
	}
	return rows, nil
}

func (s *Session) walk(root string, bulk bool) ([]gosnmp.SnmpPDU, error) {
	base := "." + mib.Norm(root)
	prefix := base + "."
	cur := base
	reps := s.g.MaxRepetitions
	if reps == 0 {
		reps = 25
	}
	var out []gosnmp.SnmpPDU
	for {
		var pkt *gosnmp.SnmpPacket
		var err error
		if bulk {
			pkt, err = s.g.GetBulk([]string{cur}, 0, reps)
		} else {
			pkt, err = s.g.GetNext([]string{cur})
		}
		if err != nil {
			return out, s.cancelled(err)
		}
		if pkt.PDUType == gosnmp.Report {
			return out, reportErr(pkt)
		}
		s.answered = true
		if pkt.Error != gosnmp.NoError {
			switch {
			case !bulk && s.g.Version == gosnmp.Version1 && pkt.Error == gosnmp.NoSuchName:
				return out, nil // SNMPv1 end of MIB view
			case bulk && pkt.Error == gosnmp.TooBig && reps > 1:
				reps = max(reps/2, 1)
				continue
			}
			return out, &AgentError{OID: mib.Norm(root), Status: pkt.Error, Rows: len(out)}
		}
		if len(pkt.Variables) == 0 {
			if bulk {
				return out, fmt.Errorf("%s: empty GETBULK response after %d rows", mib.Norm(root), len(out))
			}
			return out, nil
		}
		for _, v := range pkt.Variables {
			name := "." + mib.Norm(v.Name)
			switch v.Type {
			case gosnmp.EndOfMibView, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
				return out, nil
			}
			if !strings.HasPrefix(name, prefix) {
				return out, nil // walked past the subtree
			}
			if !OIDLess(cur, name) {
				return out, fmt.Errorf("%s: OID not increasing (%s after %s)", mib.Norm(root), mib.Norm(name), mib.Norm(cur))
			}
			v.Name = name
			out = append(out, v)
			cur = name
		}
		if len(out) > maxRows {
			return out, fmt.Errorf("%s: more than %d rows; stopped", mib.Norm(root), maxRows)
		}
	}
}

// OIDLess compares dotted OIDs numerically, component by component.
func OIDLess(a, b string) bool {
	x, y := strings.Split(mib.Norm(a), "."), strings.Split(mib.Norm(b), ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] == y[i] {
			continue
		}
		p, e1 := strconv.ParseUint(x[i], 10, 32)
		q, e2 := strconv.ParseUint(y[i], 10, 32)
		if e1 != nil || e2 != nil {
			return x[i] < y[i]
		}
		return p < q
	}
	return len(x) < len(y)
}
