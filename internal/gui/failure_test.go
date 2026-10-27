package gui

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/orionparker33/atlas-portmap/internal/output"
)

func TestFailureMessage(t *testing.T) {
	sw := func(kind string) output.SwitchSummary {
		return output.SwitchSummary{Target: "x", Error: "e", ErrorKind: kind}
	}
	for _, c := range []struct {
		switches []output.SwitchSummary
		want     string
	}{
		{[]output.SwitchSummary{sw("wrong-digest")}, "1 switch rejected the SNMPv3 credentials: check the user, the passphrases and the auth and privacy protocols; see Switches"},
		{[]output.SwitchSummary{sw("no-response"), sw("no-response")}, "2 switches did not respond: check the addresses, the community or SNMPv3 credentials, SNMP access lists and firewalls; see Switches"},
		{[]output.SwitchSummary{sw("no-response"), sw("auth-failed"), sw("decryption"), sw("access-denied")},
			"4 switches failed: 1 did not respond, 2 rejected the SNMPv3 credentials, 1 refused access; see Switches"},
		{[]output.SwitchSummary{sw("")}, "1 switch failed; see Switches"}, // a report from before error_kind
		{[]output.SwitchSummary{sw("port-closed"), {Target: "y", Error: "e", Partial: true}}, "1 switch had no SNMP agent listening: enable SNMP on the device (Cisco Small Business: snmp-server server); see Switches"},
	} {
		if got := failureMessage(&output.Report{Switches: c.switches}); got != c.want {
			t.Errorf("got  %q\nwant %q", got, c.want)
		}
	}
}

// A scan whose only switch is silent fails with a kind-specific message and error_kind set.
func TestScanFailureIsClassified(t *testing.T) {
	s := testServer()
	body := fmt.Sprintf(`{"switches":%q,"snmp":{"version":"2c","community":"x","timeout_ms":300,"retries":0},"options":{"arp_from_switches":true}}`, silentPort(t))
	w := do(t, s, call{method: "POST", path: "/api/scans", body: body})
	var v jobView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || w.Code != 202 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	v = wait(t, s, v.ID, func(v jobView) bool { return v.State != "running" })
	if v.State != "failed" || !strings.HasPrefix(v.Error, "1 switch did not respond") || v.Report.Switches[0].ErrorKind != "no-response" ||
		!strings.Contains(v.Report.Switches[0].Hint, "wrong community") || strings.Contains(v.Report.Switches[0].Hint, `"x"`) {
		t.Errorf("state %s error %q switch %+v", v.State, v.Error, v.Report.Switches[0])
	}
}
