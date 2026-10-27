package localarp

import (
	"testing"

	"github.com/orionparker33/atlas-portmap/internal/collect"
)

func ips(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %v, want %v", name, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: got %v, want %v", name, got, want)
			return
		}
	}
}

func TestParsers(t *testing.T) {
	var s []string
	for _, e := range ParseIPNeigh(`10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
10.0.0.9 dev eth0 FAILED
10.0.0.7 dev eth0 lladdr 00:11:22:33:44:77 router STALE
fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
10.0.0.8 dev eth0 INCOMPLETE
`) {
		s = append(s, e.IP.String()+"="+e.MAC.String())
	}
	ips(t, "ip neigh", s, "10.0.0.1=00:11:22:33:44:55", "10.0.0.7=00:11:22:33:44:77", "fe80::1=00:11:22:33:44:55")

	s = nil
	for _, e := range ParseProcARP(`IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         00:11:22:33:44:55     *        eth0
10.0.0.5         0x1         0x0         00:00:00:00:00:00     *        eth0
`) {
		s = append(s, e.IP.String())
	}
	ips(t, "/proc/net/arp", s, "10.0.0.1")

	s = nil
	for _, e := range ParseWindowsARP(`
Interface: 10.0.0.50 --- 0x5
  Internet Address      Physical Address      Type
  10.0.0.1              00-11-22-33-44-55     dynamic
  10.0.0.255            ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  10.0.0.2              00-11-22-33-44-66     dynamisch
`) {
		s = append(s, e.IP.String()+"="+e.MAC.String())
	}
	ips(t, "windows", s, "10.0.0.1=00:11:22:33:44:55", "10.0.0.2=00:11:22:33:44:66")

	s = nil
	for _, e := range ParseBSDARP(`? (10.0.0.1) at 0:11:22:3:44:55 on en0 ifscope [ethernet]
? (10.0.0.4) at (incomplete) on en0 ifscope [ethernet]
gw.lab (10.0.0.254) at 00:11:22:33:44:fe on en0 ifscope permanent [ethernet]
`) {
		s = append(s, e.IP.String()+"="+e.MAC.String())
	}
	ips(t, "bsd", s, "10.0.0.1=00:11:22:03:44:55", "10.0.0.254=00:11:22:33:44:fe")
}

func TestParsersKeepTheInterface(t *testing.T) {
	ifaceOf := func(e []collect.ARPEntry) []string {
		var s []string
		for _, x := range e {
			s = append(s, x.IP.String()+"@"+x.Iface)
		}
		return s
	}
	ips(t, "ip neigh", ifaceOf(ParseIPNeigh("10.0.0.1 dev eth0.60 lladdr 00:11:22:33:44:55 REACHABLE\n")), "10.0.0.1@eth0.60")
	ips(t, "/proc/net/arp", ifaceOf(ParseProcARP("IP address HW type Flags HW address Mask Device\n10.0.0.1 0x1 0x2 00:11:22:33:44:55 * wlan0\n")), "10.0.0.1@wlan0")
	ips(t, "windows", ifaceOf(ParseWindowsARP("\nInterface: 10.0.0.50 --- 0x5\n  10.0.0.1   00-11-22-33-44-55   dynamic\nSchnittstelle: 10.0.1.50 --- 0xb\n  10.0.1.1   00-11-22-33-44-66   dynamisch\n")),
		"10.0.0.1@10.0.0.50", "10.0.1.1@10.0.1.50")
	ips(t, "bsd", ifaceOf(ParseBSDARP("? (10.0.0.1) at 0:11:22:3:44:55 on en7 ifscope [ethernet]\n")), "10.0.0.1@en7")
}
