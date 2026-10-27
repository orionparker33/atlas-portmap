package main

import (
	"bytes"
	"context"
	"flag"
	"strings"
	"testing"
)

func init() { desktop = func() bool { return false } }

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsagePaths(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{nil, exitUsage, "Usage:"},
		{[]string{"frobnicate"}, exitUsage, "unknown command"},
		{[]string{"version"}, exitOK, "atlas-portmap dev"},
		{[]string{"help"}, exitOK, "Usage:"},
		{[]string{"map"}, exitUsage, "no switches"},
		{[]string{"-o", "yaml", "10.0.0.1"}, exitUsage, "unknown output format"},
		{[]string{"-mac-format", "weird", "10.0.0.1"}, exitUsage, "mac-format"},
		{[]string{"-column", "poe", "10.0.0.1"}, exitUsage, "bad column"},
		{[]string{"-column", "a=1.3.6.1.4.1.9.1,a=1.3.6", "10.0.0.1"}, exitUsage, "duplicate"},
		{[]string{"-vlans", "10-5", "10.0.0.1"}, exitUsage, "bad VLAN list"},
		{[]string{"-v", "3", "10.0.0.1"}, exitUsage, "needs a user"},
		{[]string{"-cisco-per-vlan", "maybe", "10.0.0.1"}, exitUsage, "auto, on or off"},
		{[]string{"-inventory", "/nonexistent/devices.csv"}, exitUsage, "no such file"},
		{[]string{"vendor"}, exitUsage, "usage"},
		{[]string{"vendor", "00:00:0c:01:02:03", "1.3.6.1.4.1.9.1.1"}, exitOK, "Cisco"},
		{[]string{"vendor", "nonsense"}, exitUsage, "neither"},
		{[]string{"walk"}, exitUsage, "no device"},
		{[]string{"10.0.0.1", "-o", "yaml"}, exitUsage, "unknown output format"}, // flags after a target
		{[]string{"map", "10.0.0.1", "-v", "3"}, exitUsage, "needs a user"},
		{[]string{"gui", "-addr", "0.0.0.0:0", "-no-browser"}, exitFailed, "not a loopback address"},
		{[]string{"gui", "-open", "/nonexistent.json"}, exitUsage, "no such file"},
		{[]string{"gui", "-addr", "bogus::addr", "-no-browser"}, exitFailed, "atlas-portmap gui"},
	} {
		code, out, errb := runCLI(c.args...)
		if code != c.code || !strings.Contains(out+errb, c.want) {
			t.Errorf("%v: code %d, out %q, err %q; want code %d containing %q", c.args, code, out, errb, c.code, c.want)
		}
	}
}

func TestSecretOnArgvWarns(t *testing.T) {
	_, _, errb := runCLI("-c", "s3cret", "-o", "yaml", "10.0.0.1")
	if !strings.Contains(errb, "visible in process listings") || strings.Contains(errb, "s3cret") {
		t.Errorf("warning missing or secret echoed: %q", errb)
	}
}

func TestParseFlags(t *testing.T) {
	for _, c := range []struct {
		args []string
		pos  string
		out  string
	}{
		{[]string{"10.0.0.1", "-o", "json", "10.0.0.2"}, "10.0.0.1,10.0.0.2", "json"},
		{[]string{"-o", "csv", "a", "b"}, "a,b", "csv"},
		{[]string{"a", "--", "-o", "b"}, "a,-o,b", "table"},
		{nil, "", "table"},
	} {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		o := fs.String("o", "table", "")
		pos, err := parseFlags(fs, c.args)
		if err != nil || strings.Join(pos, ",") != c.pos || *o != c.out {
			t.Errorf("%v: pos %v o %q err %v", c.args, pos, *o, err)
		}
	}
}
