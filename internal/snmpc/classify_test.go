package snmpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// sg300 is an engine ID in the form the Cisco SG300-10 uses (RFC 3411 MAC format, enterprise
// 9, Cisco's 00:76:86 OUI); the NIC bytes are made up.
var sg300 = []byte{0x80, 0x00, 0x00, 0x09, 0x03, 0x00, 0x76, 0x86, 0x00, 0x00, 0x01}

const (
	secretCommunity = "c0mmun1ty-s3cret"
	secretAuth      = "auth-pass-s3cret"
	secretPriv      = "priv-pass-s3cret"
)

func v3cfg(auth, priv string) Config {
	return Config{Port: 161, Version: V3, V3User: "mapper", V3AuthProto: auth, V3AuthPass: secretAuth, V3PrivProto: priv, V3PrivPass: secretPriv,
		Timeout: 3 * time.Second, Retries: 1}
}

func v2cfg(community string, defaulted bool) Config {
	return Config{Port: 161, Version: V2c, Community: community, CommunityDefaulted: defaulted, Timeout: 3 * time.Second, Retries: 1}
}

func timeoutErr() error {
	return fmt.Errorf("request timeout (after 1 retries): %w", gosnmp.ErrMaxRetriesExceeded)
}

func TestClassify(t *testing.T) {
	notAuth := errors.New("incoming packet is not authentic, discarding")
	refused := &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)}
	for _, c := range []struct {
		name     string
		err      error
		cfg      Config
		engine   []byte
		report   string
		answered bool
		kind     Kind
		fatal    bool
		hint     []string // substrings the hint must contain
		not      []string // and must not
	}{
		{"cancelled", fmt.Errorf("x: %w", context.DeadlineExceeded), v2cfg("c", false), nil, "", false, KindCancelled, true, []string{"-deadline"}, nil},
		{"sentinel unknown user", gosnmp.ErrUnknownUsername, v3cfg("sha", "aes"), nil, "", false, KindUnknownUser, true, []string{`"mapper"`}, nil},
		{"sentinel wrong digest", fmt.Errorf("x: %w", gosnmp.ErrWrongDigest), v3cfg("md5", "des"), nil, "", false, KindWrongDigest, true, []string{"auth passphrase", "md5"}, []string{"DES privacy"}},
		{"sentinel security level", gosnmp.ErrUnknownSecurityLevel, v3cfg("sha", "none"), nil, "", false, KindSecurityLevel, false, []string{"authNoPriv", "-v3-priv-proto"}, nil},
		{"sentinel decryption", gosnmp.ErrDecryption, v3cfg("sha", "aes"), nil, "", false, KindDecryption, true, []string{"privacy passphrase", "-v3-priv-proto des"}, nil},
		{"sentinel time window", gosnmp.ErrNotInTimeWindow, v3cfg("sha", "aes"), nil, "", false, KindTimeWindow, true, []string{"time window"}, nil},
		{"not authentic, no report", notAuth, v3cfg("sha", "aes"), sg300, "", false, KindAuthFailed, true,
			[]string{"wrong user name, auth passphrase or auth protocol, or wrong privacy protocol", "-v3-priv-proto des", "Sx300"}, nil},
		{"not authentic, DES configured", notAuth, v3cfg("sha", "des"), sg300, "", false, KindAuthFailed, true, []string{"authentication failed"}, []string{"DES"}},
		{"not authentic, authNoPriv", notAuth, v3cfg("sha", "none"), nil, "", false, KindAuthFailed, true, nil, []string{"DES"}},
		{"report wrong digest", notAuth, v3cfg("sha", "aes"), sg300, ".1.3.6.1.6.3.15.1.1.5.0", false, KindWrongDigest, true, []string{"auth passphrase, or wrong auth protocol (-v3-auth-proto is sha)", "unauthenticated Report"}, nil},
		{"report unknown user", notAuth, v3cfg("sha", "aes"), sg300, ".1.3.6.1.6.3.15.1.1.3.0", false, KindUnknownUser, true, []string{`"mapper" is not configured`}, nil},
		{"report decryption", notAuth, v3cfg("sha", "aes"), sg300, ".1.3.6.1.6.3.15.1.1.6.0", false, KindDecryption, true, []string{"-v3-priv-proto des", "Sx300"}, nil},
		{"report decryption aes256", notAuth, v3cfg("sha", "aes256"), nil, ".1.3.6.1.6.3.15.1.1.6.0", false, KindDecryption, true, []string{"aes256c", "-v3-priv-proto des"}, []string{"Sx300"}},
		{"report security level", notAuth, v3cfg("sha", "none"), sg300, ".1.3.6.1.6.3.15.1.1.1.0", false, KindSecurityLevel, true, []string{"authNoPriv"}, nil},
		// The real SG300 answers AES requests it cannot decrypt with notInTimeWindow Reports.
		{"report time window, AES to Cisco", notAuth, v3cfg("sha", "aes"), sg300, ".1.3.6.1.6.3.15.1.1.2.0", false, KindTimeWindow, true, []string{"privacy protocol", "-v3-priv-proto des", "Sx300"}, nil},
		{"report time window, DES", notAuth, v3cfg("sha", "des"), sg300, ".1.3.6.1.6.3.15.1.1.2.0", false, KindTimeWindow, true, []string{"engine time"}, []string{"DES privacy"}},
		{"report unknown engine", notAuth, v3cfg("sha", "aes"), sg300, ".1.3.6.1.6.3.15.1.1.4.0", false, KindAuthFailed, true, []string{"usmStatsUnknownEngineIDs"}, nil},
		{"report not usmStats", notAuth, v3cfg("sha", "aes"), sg300, ".1.3.6.1.6.3.11.2.1.1.0", false, KindAuthFailed, true, []string{"does not say which"}, nil},
		{"v2c timeout, default public", timeoutErr(), v2cfg("public", true), nil, "", false, KindNoResponse, true,
			[]string{"no answer (2 requests, timeout 3s, UDP 161)", "wrong community", "snmp-server server", `default "public"`}, nil},
		{"v2c timeout, explicit community", timeoutErr(), v2cfg(secretCommunity, false), nil, "", false, KindNoResponse, true, []string{"wrong community"}, []string{"public"}},
		{"v2c timeout, explicit public", timeoutErr(), v2cfg("public", false), nil, "", false, KindNoResponse, true, nil, []string{"public"}},
		{"net timeout", &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}, v2cfg("c", false), nil, "", false, KindNoResponse, true, nil, nil},
		{"v3 discovery timeout", timeoutErr(), v3cfg("sha", "aes"), nil, "", false, KindNoResponse, true, []string{"engine discovery", "host down"}, []string{"DES"}},
		{"v3 timeout after discovery", timeoutErr(), v3cfg("sha", "aes"), sg300, "", false, KindV3NoResponse, true,
			[]string{"80:00:00:09:03:00:76:86:00:00:01, Cisco", "drop requests with wrong credentials", "-v3-priv-proto des"}, nil},
		{"v3 timeout after answers", timeoutErr(), v3cfg("sha", "aes"), sg300, "", true, KindNoResponse, true, []string{"stopped answering part-way", "-max-reps"}, []string{"credentials"}},
		{"port closed", fmt.Errorf("error reading from socket: %w", refused), v2cfg("c", false), nil, "", false, KindPortClosed, false,
			[]string{"nothing listens on UDP 161", "snmp-server server"}, nil},
		{"denied v2c", &AgentError{OID: "1.3.6.1.2.1.1.5.0", Status: gosnmp.NoAccess, get: true}, v2cfg(secretCommunity, false), nil, "", true, KindAccessDenied, false,
			[]string{"(noAccess)", "community has no read access"}, nil},
		{"denied v3 noAuthNoPriv", &AgentError{OID: "1.3.6.1.2.1.1.5", Status: gosnmp.AuthorizationError}, v3cfg("none", "none"), sg300, "", true, KindAccessDenied, false,
			[]string{"(authorizationError)", "noAuthNoPriv", "-v3-auth-proto and -v3-priv-proto"}, nil},
		{"denied v3 authPriv", fmt.Errorf("getbulk and getnext: %w", &AgentError{Status: gosnmp.AuthorizationError}), v3cfg("sha", "aes"), sg300, "", true, KindAccessDenied, false,
			[]string{"no read view", "-v3-context"}, []string{"-v3-auth-proto"}},
		{"genErr is not denial", &AgentError{OID: "1.3.6.1.2.1.1.5.0", Status: gosnmp.GenErr, get: true}, v2cfg("c", false), nil, "", true, KindOther, false, nil, nil},
		{"other", errors.New("1.3.6: OID not increasing (1.3.6.1 after 1.3.6.2)"), v2cfg("c", false), nil, "", true, KindOther, false, nil, nil},
		// A walk's two errors: one fatal part makes the whole fatal, as Fatal's substring list did.
		{"mixed walk error", fmt.Errorf("getbulk: unknown security level; getnext: %w", timeoutErr()), v3cfg("sha", "aes"), sg300, "", true, KindNoResponse, true, nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := classify(c.err, c.cfg, c.engine, c.report, c.answered)
			// Fatal goes by the error itself: a Report only explains a "not authentic" failure.
			if e.Kind != c.kind || Fatal(c.err) != c.fatal {
				t.Errorf("kind %s (Fatal %v), want %s (fatal %v); hint %q", e.Kind, Fatal(c.err), c.kind, c.fatal, e.Hint)
			}
			if e.Error() != c.err.Error() || !errors.Is(e, c.err) {
				t.Errorf("Error() %q does not carry %q", e.Error(), c.err)
			}
			for _, s := range c.hint {
				if !strings.Contains(e.Hint, s) {
					t.Errorf("hint %q lacks %q", e.Hint, s)
				}
			}
			for _, s := range append(c.not, secretCommunity, secretAuth, secretPriv) {
				if strings.Contains(e.Hint, s) {
					t.Errorf("hint %q contains %q", e.Hint, s)
				}
			}
		})
	}
}

// legacyFatal is Fatal before the classifier: a list of substrings. The classifier must keep
// the same set of fatal errors (making authorizationError fatal would break the GETNEXT
// fallback for agents that refuse only GETBULK).
func legacyFatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	for _, w := range []string{"timeout", "authentic", "unknown user", "wrong digest", "decryption", "not in time window"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func TestFatalUnchanged(t *testing.T) {
	refused := fmt.Errorf("error reading from socket: %w", &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)})
	for _, err := range []error{
		nil, context.Canceled, timeoutErr(), errors.New("incoming packet is not authentic, discarding"),
		errors.New("message is not authenticated but user \"u\" requires authentication"),
		gosnmp.ErrUnknownUsername, gosnmp.ErrWrongDigest, gosnmp.ErrDecryption, gosnmp.ErrNotInTimeWindow,
		gosnmp.ErrUnknownSecurityLevel, gosnmp.ErrUnknownEngineID, gosnmp.ErrUnknownReportPDU, gosnmp.ErrInvalidMsgs,
		errors.New("engine discovery response has an invalid authoritative engine ID"), refused,
		&AgentError{Status: gosnmp.AuthorizationError}, &AgentError{Status: gosnmp.NoAccess}, &AgentError{Status: gosnmp.GenErr},
		fmt.Errorf("getbulk: %v; getnext: %w", &AgentError{Status: gosnmp.AuthorizationError}, &AgentError{Status: gosnmp.GenErr}),
		errors.New("1.3.6: empty GETBULK response after 0 rows"), errors.New("error establishing connection to host: lookup x: no such host"),
		&Error{Kind: KindDecryption, Err: errors.New("incoming packet is not authentic, discarding")},
	} {
		if Fatal(err) != legacyFatal(err) {
			t.Errorf("Fatal(%v) = %v, was %v", err, Fatal(err), legacyFatal(err))
		}
	}
}

func TestExplain(t *testing.T) {
	inner := &Error{Kind: KindWrongDigest, Hint: "h", Err: errors.New("incoming packet is not authentic, discarding")}
	if e := Explain(fmt.Errorf("ctx: %w", inner), Config{}); e != inner {
		t.Errorf("Explain dropped the session's classification: %+v", e)
	}
	if e := Explain(timeoutErr(), v2cfg("public", true)); e.Kind != KindNoResponse || !strings.Contains(e.Hint, "public") {
		t.Errorf("Explain = %+v", e)
	}
	if Explain(nil, Config{}) != nil {
		t.Error("Explain(nil) != nil")
	}
}

func TestEngineEnterprise(t *testing.T) {
	if enterprise(sg300) != 9 || enterprise([]byte{0, 0, 0x0b, 0x6e, 1, 2, 3, 4, 5, 6, 7, 8}) != 2926 || enterprise([]byte{1, 2}) != -1 {
		t.Error("enterprise")
	}
	if got := engineText(sg300); got != "80:00:00:09:03:00:76:86:00:00:01, Cisco" {
		t.Errorf("engineText = %q", got)
	}
}
