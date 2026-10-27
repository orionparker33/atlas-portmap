package snmpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]Version{"1": V1, "v1": V1, "2c": V2c, "2": V2c, "V2C": V2c, "3": V3, "v3": V3} {
		if got, err := ParseVersion(in); err != nil || got != want {
			t.Errorf("ParseVersion(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseVersion("4"); err == nil {
		t.Error("ParseVersion(4) accepted")
	}
}

func TestValidate(t *testing.T) {
	base := Config{Timeout: time.Second, Retries: 1}
	ok := []Config{
		withV(base, V2c, func(c *Config) { c.Community = "public" }),
		withV(base, V3, func(c *Config) { c.V3User = "u"; c.V3AuthProto = "none"; c.V3PrivProto = "none" }),
		withV(base, V3, func(c *Config) {
			c.V3User = "u"
			c.V3AuthProto = "sha256"
			c.V3AuthPass = "12345678"
			c.V3PrivProto = "aes256"
			c.V3PrivPass = "abcdefgh"
		}),
	}
	for i, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := []Config{
		withV(base, V2c, nil), // no community
		withV(base, V3, nil),  // no user
		withV(base, V3, func(c *Config) {
			c.V3User = "u"
			c.V3AuthProto = "none"
			c.V3PrivProto = "aes"
			c.V3PrivPass = "abcdefgh"
		}),
		withV(base, V3, func(c *Config) { c.V3User = "u"; c.V3AuthProto = "sha"; c.V3AuthPass = "short"; c.V3PrivProto = "none" }),
		withV(base, V3, func(c *Config) { c.V3User = "u"; c.V3AuthProto = "rot13"; c.V3AuthPass = "12345678" }),
		withV(Config{Timeout: 0}, V2c, func(c *Config) { c.Community = "x" }),
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("bad[%d] accepted", i)
		}
	}
	// Secrets never leak through validation errors.
	c := withV(base, V3, func(c *Config) {
		c.V3User = "u"
		c.V3AuthProto = "sha"
		c.V3AuthPass = "s3cr3t"
		c.V3PrivProto = "none"
	})
	if err := c.Validate(); err == nil || containsStr(err.Error(), "s3cr3t") {
		t.Errorf("error leaked or missing: %v", err)
	}
}

func withV(c Config, v Version, f func(*Config)) Config {
	c.Version = v
	if f != nil {
		f(&c)
	}
	return c
}

func containsStr(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in, host string
		port     uint16
		ok       bool
	}{
		{"10.0.0.2", "10.0.0.2", 161, true},
		{"10.0.0.2:1161", "10.0.0.2", 1161, true},
		{"core-sw.lab", "core-sw.lab", 161, true},
		{"[fd00::2]:1161", "fd00::2", 1161, true},
		{"fd00::2", "fd00::2", 161, true},
		{"10.0.0.2:0", "", 0, false},
		{"10.0.0.2:x", "", 0, false},
		{"", "", 0, false},
	}
	for _, c := range cases {
		h, p, err := SplitTarget(c.in, 161)
		if (err == nil) != c.ok || (c.ok && (h != c.host || p != c.port)) {
			t.Errorf("SplitTarget(%q) = %q %d %v", c.in, h, p, err)
		}
	}
}

func TestFatal(t *testing.T) {
	for _, e := range []error{
		context.Canceled, fmt.Errorf("wrap: %w", context.DeadlineExceeded),
		errors.New("request timeout (after 1 retries)"), errors.New("incoming packet is not authentic, discarding"),
		errors.New("unknown user name"),
	} {
		if !Fatal(e) {
			t.Errorf("Fatal(%v) = false", e)
		}
	}
	for _, e := range []error{nil, errors.New("OID not increasing: .1.3 >= .1.3")} {
		if Fatal(e) {
			t.Errorf("Fatal(%v) = true", e)
		}
	}
}

func TestDialRejectsInvalidConfig(t *testing.T) {
	if _, err := Dial(context.Background(), "127.0.0.1", Config{Version: V2c, Timeout: time.Second}, 0); err == nil {
		t.Error("Dial accepted a config with no community")
	}
}

// gosnmp can hand back an authenticated usmStats Report as if it were the reply.
func TestReportIsAnError(t *testing.T) {
	for oid, want := range map[string]error{
		".1.3.6.1.6.3.15.1.1.2.0": gosnmp.ErrNotInTimeWindow,
		".1.3.6.1.6.3.15.1.1.4.0": gosnmp.ErrUnknownEngineID,
		".1.3.6.1.6.3.15.1.1.5.0": gosnmp.ErrUnknownReportPDU,
	} {
		err := reportErr(&gosnmp.SnmpPacket{PDUType: gosnmp.Report, Variables: []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Counter32, Value: uint(7)}}})
		if !errors.Is(err, want) || !strings.Contains(err.Error(), oid[1:]) {
			t.Errorf("%s: %v", oid, err)
		}
	}
	if k := Explain(reportErr(&gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.15.1.1.2.0"}}}), Config{Version: V3}).Kind; k != KindTimeWindow {
		t.Errorf("kind %s", k)
	}
}

func TestDialExplainsDNSFailure(t *testing.T) {
	_, err := Dial(context.Background(), "no-such-host.invalid", Config{Version: V2c, Community: "c", Port: 161, Timeout: 2 * time.Second}, 0)
	var e *Error
	if !errors.As(err, &e) || !strings.Contains(e.Hint, "resolve host name") && !strings.Contains(e.Hint, "DNS lookup") {
		t.Errorf("err %v (%T)", err, err)
	}
}
