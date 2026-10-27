package output

import (
	"bytes"
	"testing"
)

func TestWriteFailures(t *testing.T) {
	r := &Report{
		Switches: []SwitchSummary{
			{Target: "10.0.0.1", Name: "core"},
			{Target: "10.0.0.2", Error: "incoming packet is not authentic, discarding", ErrorKind: "wrong-digest", Hint: "wrong SNMPv3 auth passphrase"},
			{Target: "10.0.0.3", Name: "edge\x1b[2J", Partial: true, FDBRows: 12, Error: "dot1qTpFdbPort: request timeout", ErrorKind: "no-response", Hint: "the agent stopped answering"},
			{Target: "10.0.0.4", Error: "1.3.6: OID not increasing", ErrorKind: "other"},
		},
		ARPSources: []SourceSummary{{Target: "10.0.0.254", Error: "request timeout", ErrorKind: "no-response", Hint: "no answer"}, {Target: "10.0.0.253"}},
	}
	var b bytes.Buffer
	WriteFailures(&b, r)
	want := `error: switch 10.0.0.2: FAILED (no data) [wrong-digest]: wrong SNMPv3 auth passphrase
  cause: incoming packet is not authentic, discarding
error: switch edge [2J (10.0.0.3): PARTIAL (stopped part-way after 12 FDB rows; its rows are incomplete) [no-response]: the agent stopped answering
  cause: dot1qTpFdbPort: request timeout
error: switch 10.0.0.4: FAILED (no data): 1.3.6: OID not increasing
error: ARP source 10.0.0.254: FAILED (IP addresses from it are missing) [no-response]: no answer
  cause: request timeout
`
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}
