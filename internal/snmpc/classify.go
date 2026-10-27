package snmpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/orionparker33/atlas-portmap/internal/mib"
)

// Kind is the class of a failed SNMP exchange. The values are stable: reports carry them as
// error_kind.
type Kind string

// Error kinds.
const (
	KindCancelled     Kind = "cancelled"      // the run was cancelled or hit its deadline
	KindNoResponse    Kind = "no-response"    // nothing answered (v1/v2c, SNMPv3 discovery, or a session that went quiet)
	KindV3NoResponse  Kind = "v3-no-response" // SNMPv3 discovery answered, the authenticated request did not
	KindPortClosed    Kind = "port-closed"    // ICMP port unreachable
	KindAuthFailed    Kind = "auth-failed"    // the SNMPv3 reply failed authentication; the agent did not say why
	KindUnknownUser   Kind = "unknown-user"   // usmStatsUnknownUserNames
	KindWrongDigest   Kind = "wrong-digest"   // usmStatsWrongDigests
	KindSecurityLevel Kind = "security-level" // usmStatsUnsupportedSecLevels
	KindDecryption    Kind = "decryption"     // usmStatsDecryptionErrors
	KindTimeWindow    Kind = "time-window"    // usmStatsNotInTimeWindows after re-synchronising
	KindAccessDenied  Kind = "access-denied"  // error-status authorizationError or noAccess
	KindOther         Kind = "other"
)

// NoResponse reports the kinds in which the agent sent nothing back.
func (k Kind) NoResponse() bool { return k == KindNoResponse || k == KindV3NoResponse }

// Credentials reports the kinds in which the agent rejected the SNMPv3 credentials.
func (k Kind) Credentials() bool {
	switch k {
	case KindAuthFailed, KindUnknownUser, KindWrongDigest, KindSecurityLevel, KindDecryption, KindTimeWindow:
		return true
	}
	return false
}

// fatal kinds leave the agent unusable for the run. access-denied, security-level and
// port-closed are not fatal: an agent may refuse one subtree, or only GETBULK, and answer the
// rest, so CollectSwitch decides on its first request instead.
func (k Kind) fatal() bool {
	switch k {
	case KindCancelled, KindNoResponse, KindV3NoResponse, KindAuthFailed, KindUnknownUser, KindWrongDigest, KindDecryption, KindTimeWindow:
		return true
	}
	return false
}

// Error is a classified failure. Its text is the underlying error's, unchanged; Hint says what
// to check or change. A Hint never contains a community or passphrase ("public" only when it
// was the implicit default).
type Error struct {
	Kind Kind
	Hint string
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// AgentError is an error-status reply (RFC 3416): the agent answered and refused or failed the
// request. A walk's error carries the rows read before it.
type AgentError struct {
	OID    string           // the OID requested (a walk's root)
	Status gosnmp.SNMPError // error-status
	Rows   int              // rows a walk read before the error
	get    bool
}

func (e *AgentError) Error() string {
	if e.get {
		return fmt.Sprintf("%s: agent returned %v", e.OID, e.Status)
	}
	return fmt.Sprintf("%s: agent returned %v after %d rows", e.OID, e.Status, e.Rows)
}

// IsAgentError reports whether err is (or wraps) an error-status reply.
func IsAgentError(err error) bool {
	var ae *AgentError
	return errors.As(err, &ae)
}

// IsDenied reports whether err is (or wraps) the agent refusing this user or community
// (authorizationError, noAccess), as opposed to failing one object (genErr and the like).
func IsDenied(err error) bool {
	var ae *AgentError
	return errors.As(err, &ae) && (ae.Status == gosnmp.AuthorizationError || ae.Status == gosnmp.NoAccess)
}

// usmStats maps the RFC 3414 counter an agent names in a Report to the cause it reports.
var usmStats = map[string]Kind{
	".1.3.6.1.6.3.15.1.1.1.0": KindSecurityLevel, // usmStatsUnsupportedSecLevels
	".1.3.6.1.6.3.15.1.1.2.0": KindTimeWindow,    // usmStatsNotInTimeWindows
	".1.3.6.1.6.3.15.1.1.3.0": KindUnknownUser,   // usmStatsUnknownUserNames
	".1.3.6.1.6.3.15.1.1.4.0": KindAuthFailed,    // usmStatsUnknownEngineIDs (explained below)
	".1.3.6.1.6.3.15.1.1.5.0": KindWrongDigest,   // usmStatsWrongDigests
	".1.3.6.1.6.3.15.1.1.6.0": KindDecryption,    // usmStatsDecryptionErrors
}

const usmStatsUnknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"

// Fatal reports errors after which the agent is unusable for this run: no response, an
// SNMPv3 authentication failure, or cancellation.
func Fatal(err error) bool {
	return err != nil && classify(err, Config{}, nil, "", false).Kind.fatal()
}

// IsTimeout reports a request that got no answer.
func IsTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

// Explain returns the classification err carries (see Session.Classify), or classifies it with
// c alone, for errors that never reached a session.
func Explain(err error, c Config) *Error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return classify(err, c, nil, "", false)
}

// notAuthentic is gosnmp's (v1.47.0) only report of an SNMPv3 reply that failed authentication,
// a plain fmt.Errorf with no sentinel.
func notAuthentic(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "authentic")
}

// classify is the pure core of Session.Classify. engineID is the authoritative engine ID SNMPv3
// discovery learned (nil if none), reportOID the usmStats OID of the Report the agent sent in
// place of an authenticated reply ("" if none), and answered whether the agent had answered any
// request in this session.
//
// The rules that make an error fatal come first, so an error whose text matches several (the
// "getbulk: …; getnext: …" pair of a walk) is fatal whenever one of its parts is.
func classify(err error, c Config, engineID []byte, reportOID string, answered bool) *Error {
	if err == nil {
		return nil
	}
	e := &Error{Kind: KindOther, Err: err}
	msg := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		e.Kind, e.Hint = KindCancelled, "the run was cancelled or reached its time limit (-deadline) before this device finished"
	// gosnmp's sentinels: Reports it could authenticate (or read before discovery finished).
	case errors.Is(err, gosnmp.ErrUnknownUsername) || strings.Contains(msg, "unknown user"):
		e.Kind, e.Hint = KindUnknownUser, usmHint(KindUnknownUser, c, engineID)
	case errors.Is(err, gosnmp.ErrWrongDigest) || strings.Contains(msg, "wrong digest"):
		e.Kind, e.Hint = KindWrongDigest, usmHint(KindWrongDigest, c, engineID)
	case errors.Is(err, gosnmp.ErrDecryption) || strings.Contains(msg, "decryption"):
		e.Kind, e.Hint = KindDecryption, usmHint(KindDecryption, c, engineID)
	case errors.Is(err, gosnmp.ErrNotInTimeWindow) || strings.Contains(msg, "not in time window"):
		e.Kind, e.Hint = KindTimeWindow, usmHint(KindTimeWindow, c, engineID)
	// An unauthenticated Report (or a reply signed with another key) is discarded unread; the
	// Report recovered from the socket, if any, says why.
	case notAuthentic(err):
		e.Kind = KindAuthFailed
		if k, ok := usmStats[reportOID]; ok {
			e.Kind = k
			e.Hint = usmHint(k, c, engineID)
			if reportOID == usmStatsUnknownEngineIDs {
				e.Hint = "the agent did not accept the SNMPv3 engine ID it had announced (usmStatsUnknownEngineIDs): it may have restarted, or more than one agent answers at this address"
			}
			e.Hint += "; named in the agent's unauthenticated Report (a diagnosis, not proof)"
		} else {
			e.Hint = "SNMPv3 authentication failed: wrong user name, auth passphrase or auth protocol, or wrong privacy protocol (the agent's reply was not authenticated, so it does not say which)" + desHint(c, engineID)
		}
	case IsTimeout(err):
		e.Kind, e.Hint = noResponse(c, engineID, answered)
	case errors.Is(err, gosnmp.ErrUnknownSecurityLevel) || strings.Contains(msg, "unknown security level"):
		e.Kind, e.Hint = KindSecurityLevel, usmHint(KindSecurityLevel, c, engineID)
	// Linux and macOS report an ICMP port unreachable on a connected UDP socket. Windows does
	// not: Go turns SIO_UDP_CONNRESET off, so there a closed port is a no-response.
	case errors.Is(err, syscall.ECONNREFUSED):
		e.Kind = KindPortClosed
		e.Hint = fmt.Sprintf("ICMP port unreachable: nothing listens on UDP %d (SNMP agent disabled; Cisco Small Business: snmp-server server), or a firewall rejected the request", c.Port)
	case IsDenied(err):
		e.Kind, e.Hint = KindAccessDenied, deniedHint(err, c)
	case errors.Is(err, gosnmp.ErrUnknownEngineID) || strings.Contains(msg, "invalid authoritative engine id"):
		e.Hint = "SNMPv3 engine discovery failed: the agent announced an engine ID it then did not accept, or an invalid one; it may have restarted, or more than one agent answers at this address"
	}
	return e
}

func noResponse(c Config, engineID []byte, answered bool) (Kind, string) {
	n := c.Retries + 1
	tries := fmt.Sprintf("%d request", n)
	if n != 1 {
		tries += "s"
	}
	sent := fmt.Sprintf("(%s, timeout %s, UDP %d)", tries, c.Timeout.Round(time.Millisecond), c.Port)
	switch {
	case answered:
		return KindNoResponse, "the agent stopped answering part-way (it had answered earlier requests): it may be overloaded, rate-limiting SNMP or dropping large responses; try a lower -max-reps or a longer -timeout"
	case c.Version == V3 && len(engineID) > 0:
		return KindV3NoResponse, fmt.Sprintf("the agent answered SNMPv3 engine discovery (engine ID %s) but not the authenticated request: "+
			"some agents drop requests with wrong credentials without replying, so check the user name, the auth and privacy passphrases and protocols (-v3-auth-proto, -v3-priv-proto), and the user's group or access list",
			engineText(engineID)) + desHint(c, engineID)
	case c.Version == V3:
		return KindNoResponse, "no answer to SNMPv3 engine discovery " + sent +
			": host down or unreachable, SNMP or SNMPv3 disabled on the device (Cisco Small Business: snmp-server server), an SNMP access list or a firewall"
	}
	h := "no answer " + sent + ": a wrong community (agents drop it without replying), SNMP disabled on the device (Cisco Small Business: snmp-server server), the wrong SNMP version (-v), an SNMP access list or a firewall"
	if c.CommunityDefaulted && c.Community == "public" {
		h += `; no community was given, so the default "public" was used (set PORTMAP_COMMUNITY)`
	}
	return KindNoResponse, h
}

// usmHint explains one USM rejection (RFC 3414 3.2).
func usmHint(k Kind, c Config, engineID []byte) string {
	switch k {
	case KindUnknownUser:
		return fmt.Sprintf("SNMPv3 user %q is not configured on this agent (or only under another engine ID)", c.V3User)
	case KindWrongDigest:
		return fmt.Sprintf("wrong SNMPv3 auth passphrase, or wrong auth protocol (-v3-auth-proto is %s)", protoName(c.V3AuthProto))
	case KindDecryption:
		return fmt.Sprintf("the agent could not decrypt the request: wrong privacy passphrase, or wrong privacy protocol (-v3-priv-proto is %s)", protoName(c.V3PrivProto)) +
			desHint(c, engineID) + aesHint(c)
	case KindSecurityLevel:
		return fmt.Sprintf("SNMPv3 user %q may not use %s on this agent: set -v3-auth-proto and -v3-priv-proto to the security level of the user's group", c.V3User, level(c))
	case KindTimeWindow:
		// Cisco SG300 (1.4.11.2) answers a request it cannot decrypt (AES to a DES-only agent)
		// with notInTimeWindow Reports rather than decryptionErrors, so a privacy mismatch is the
		// likelier cause whenever one is possible.
		if h := desHint(c, engineID); h != "" {
			return "SNMPv3 request rejected as outside the time window even after re-synchronising, which some agents report when they cannot decrypt the request: check the privacy protocol and passphrase" + h
		}
		return "SNMPv3 time window: the agent still rejected the request after re-synchronising to its engine time; retry, and check whether another device shares this agent's engine ID"
	}
	return ""
}

func deniedHint(err error, c Config) string {
	var ae *AgentError
	errors.As(err, &ae)
	status := ae.Status.String()
	status = strings.ToLower(status[:1]) + status[1:] // authorizationError, as RFC 3416 spells it
	switch {
	case c.Version != V3:
		return fmt.Sprintf("the agent refused the request (%s): this community has no read access to it (community or view configuration)", status)
	case level(c) != "authPriv":
		return fmt.Sprintf("the agent refused the request (%s): user %q may not read at %s; its group probably requires a higher security level, so set -v3-auth-proto and -v3-priv-proto to match the group", status, c.V3User, level(c))
	}
	return fmt.Sprintf("the agent refused the request (%s): user %q's group has no read view for it, or the context (-v3-context) is wrong", status, c.V3User)
}

// desHint suggests DES for an SNMPv3 failure a privacy-protocol mismatch would explain: some
// agents, Cisco Small Business Sx300/Sx500 on 1.4.x firmware among them, offer only DES.
func desHint(c Config, engineID []byte) string {
	pp, err := privProto(c.V3PrivProto)
	if c.Version != V3 || err != nil || pp == gosnmp.NoPriv || pp == gosnmp.DES {
		return ""
	}
	if enterprise(engineID) == mib.EnterpriseCisco {
		return "; this agent may only support DES privacy (try -v3-priv-proto des; Cisco Small Business Sx300/Sx500 switches on 1.4.x firmware do)"
	}
	return "; this agent may only support DES privacy (try -v3-priv-proto des)"
}

// aesHint covers the two incompatible AES-192/256 key extensions.
func aesHint(c Config) string {
	switch pp, _ := privProto(c.V3PrivProto); pp {
	case gosnmp.AES192, gosnmp.AES256:
		return "; Cisco extends AES-192/256 keys differently (Reeder): try aes192c/aes256c"
	case gosnmp.AES192C, gosnmp.AES256C:
		return "; most non-Cisco agents extend AES-192/256 keys the Blumenthal way: try aes192/aes256"
	}
	return ""
}

// level names the SNMPv3 security level c asks for.
func level(c Config) string {
	ap, _ := authProto(c.V3AuthProto)
	pp, _ := privProto(c.V3PrivProto)
	switch {
	case ap == gosnmp.NoAuth:
		return "noAuthNoPriv"
	case pp == gosnmp.NoPriv:
		return "authNoPriv"
	}
	return "authPriv"
}

func protoName(s string) string {
	if s == "" {
		return "none"
	}
	return strings.ToLower(s)
}

// enterprise is the IANA enterprise number in an SNMP engine ID's first four octets (RFC 3411,
// and the older 12-octet format alike), or -1. It comes from an unauthenticated discovery
// Report: good for a hint, never for a verdict.
func enterprise(id []byte) int {
	if len(id) < 5 {
		return -1
	}
	return int(binary.BigEndian.Uint32(id[:4]) & 0x7fffffff)
}

func engineText(id []byte) string {
	h := make([]string, len(id))
	for i, b := range id {
		h[i] = fmt.Sprintf("%02x", b)
	}
	s := strings.Join(h, ":")
	switch n := enterprise(id); {
	case n == mib.EnterpriseCisco:
		s += ", Cisco"
	case n > 0:
		s += fmt.Sprintf(", enterprise %d", n)
	}
	return s
}
