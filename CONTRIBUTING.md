# Contributing

Issues and pull requests are welcome. Before opening a PR, run `make vet test`, and `make e2e`
(needs python3) if you changed collection, the engine or the GUI API. Contributions are accepted
under the MIT license.

## Device captures

Support for more switch families depends on recordings from real devices. Only submit captures of
devices you own or are authorized to share.

1. Walk the device read-only:
   `atlas-portmap walk [SNMP flags] HOST 1.3.6.1.2.1 1.0.8802.1.1.2 1.2.840.10006.300.43 > walk.txt`
   (add vendor subtrees the device needs, such as CISCO-VTP-MIB `1.3.6.1.4.1.9.9.46`).
2. Convert and anonymize: `go run ./tools/walk2snmprec -anon walk.txt > device.snmprec`. MAC NIC
   bytes get random values each run, serial numbers become zeros, sysContact and sysLocation are
   blanked.
3. Read the result before sharing it: sysName, ifAlias port descriptions, LLDP/CDP neighbour names,
   VLAN names and IP addresses are kept and may identify your network. Never attach the raw walk.
