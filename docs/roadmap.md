# atlas-portmap: improvement roadmap for the multi-client field engineer

Date: 2026-10-27. Built from public web research in five areas (competitors, field testers, MSP workflow, technical depth, security operations), followed by a verification pass against the code, MIBs and vendor sources: 69 raw findings became 30 improvements, 15 rejected items and 12 gaps.

**Evidence marks**
- **verified**: the research checked it against the code, a MIB or a vendor source.
- **inferred**: follows from the evidence.
- **unverified**: reported but not checked.

Value (1-5), effort (S/M/L) and tier come from the research. Rank is a judgement call; the rule is in §3.

## 1. Summary

- **Real hardware first.** The base mapper collects the right core data: Q-BRIDGE/BRIDGE FDB, ARP/ND, LLDP/CDP, Cisco per-VLAN instances and cascaded edge placement. Apart from three Cisco SMB switches (an SG300-10, whose recording is an e2e fixture, and two SG350-28), it has only run against an SNMP simulator (README). Milestone 1 is about getting through real client switches safely: per-device pacing (WS-05), a field SNMP doctor with redacted capture and replay (FW-06), and a vendor support matrix built from those captures.
- **The largest risk is outside the feature list.** These decide whether the base map works at a given client, and none of them is planned yet:
  - proprietary FDB MIBs (Comware hh3c, Huawei L2MAM, some Extreme/Avaya lines);
  - Juniper ELS VLAN-to-FID mapping;
  - Aruba AOS-CX and FortiSwitch quirks;
  - the LLDP-V2-MIB tree;
  - SMB "smart" switches.
- **Biggest field time savers:**
  - "Where am I plugged in?" (FW-01)
  - read-only replug and watch locate (FW-04)
  - table warm-up and dwell (FW-03)
  - seed-and-crawl discovery (FW-02)
- **Client separation is the main structural gap.** Today GUI scans live in memory only, and the client label is free text (verified). Four items should ship as one milestone, not one at a time:
  - workspaces (WS-01);
  - CIDR-scoped credential references (WS-02);
  - a scope guard with network fingerprint and SNMPv3 engine-ID pin (WS-03);
  - per-client age encryption (WS-04).
- **Billable output.** Four items turn a map into something billable:
  - the visit deliverable (OUT-01);
  - port health (DA-04);
  - observational L2 findings (SEC-01);
  - visit-to-visit diff (DA-01).

  Everything stays read-only, with no SET anywhere. Every rejected item is an active attack, credential guessing or scope creep.
- **GUI extension contract first.** Before features land, the GUI needs one contract: faceplate overlay, port-drawer section, badge, a shared Finding model and a virtualised Results table. About ten items add faceplate overlays. Without the contract, each one wires up its own view.

## 2. The multi-client engineer's workflow

| Stage | Engineer's question | atlas-portmap today | Roadmap |
|---|---|---|---|
| Arrive | Which client network is this? Where am I plugged in? | Nothing. The label is free text and there is no network check. | WS-01, WS-03, FW-01 |
| Connect | Which credentials apply here? Why does SNMP fail? | Secrets come from env vars (1Password CLI injection). Failures are not diagnosed. | WS-02, FW-06, WS-05 |
| Discover | Which switches exist? | Targets are given by hand. There is no crawl: `collect.Neighbor` has no management address, and `oids.go` has neither lldpRemManAddr nor cdpCacheAddress (verified). | FW-02, FW-01 (seed) |
| Map | Which port is each device on? | Strongest area: FDB, ARP/ND, LLDP/CDP, Cisco per-VLAN, cascaded edge placement. There is no ping sweep (verified, README). Tested on three Cisco SMB switches (SG300-10, SG350-28) so far (README). | FW-03, FW-06, DA-08, PL-01 |
| Troubleshoot | Slow, dropping, unpowered, wrong VLAN? | IF-MIB status and speed, PVID, 802.1X port-control column. No error counters (verified, `oids.go`). The README PoE example is broken (verified). | FW-04, DA-04, DA-03, DA-06, DA-05 |
| Document | What do I leave behind? | Terminal table, JSON, CSV, and the GUI Results/Switches/Ports views. | OUT-01, OUT-02, FW-05, DA-07, DA-08 |
| Hand over | To whom, in what form, how protected? | Plain files. No report, no redaction. | OUT-01, WS-04, OUT-03 |
| Revisit | What changed? Is this device normal here? | Nothing persists between GUI sessions (verified). | WS-01, DA-01, DA-02 |

Fit today: strong at Map, partial at Troubleshoot and Document, absent at Arrive, Discover, Hand over and Revisit.

## 3. Prioritised roadmap

**Ranking rule.** Items are ranked by value to the multi-client engineer first, then adjust for three things:
- (a) risk reduction before the first real-client run;
- (b) how many other items depend on it;
- (c) effort.

WS-05 ranks above its value score because of (a). WS-04 ranks above its value score because of (b): WS-01 creates the data liability it covers.

### 3.0 Prerequisites (from verified bugs and research gaps)

| # | Item | Effort | Why |
|---|---|---|---|
| P1 | **Done (2026-10-27).** Fix the README PoE example (`-column poe=1.3.6.1.2.1.105.1.1.1.6`). Make `-column` reject OIDs with a multi-component index, with a clear error (from DA-05). | S | Verified bug. pethPsePortTable is indexed group.port, and `collect.extra -> intRows -> mib.Int` rejects multi-component indexes. On RFC 3621 agents the column comes back empty with "no rows indexed by ifIndex". |
| P2 | A documented exit-code table for every subcommand. | S | Exit 3 already means "partial" (verified, `main.go` and README). Diff "changes found" needs a new code, for example 4. WS-05 aborts map to 3. |
| P3 | GUI extension contract: an overlay / drawer-section / badge registry, one Finding model, a virtualised Results table for 10k+ MACs, and colour-blind-safe overlay palettes with legends. | M (est.) | About ten items add faceplate overlays, drawer sections or badges. This is what makes the GUI expandable. |
| P4 | Vendor support matrix and lab hardware list, filled from FW-06 captures. | ongoing | Decides per vendor whether the base map works. SMB smart switches are not researched yet. |
| P5 | Field-laptop release hygiene: Authenticode signing, macOS notarisation, an allow-listing note for the client's SOC, and a documented non-admin fallback for every privileged feature. | S-M (est.) | SmartScreen and EDR block or flag unsigned SNMP scanners on MSP and client machines. |
| P6 | Headless parity: every new feature reachable from the CLI, documented `ssh -L` for the loopback GUI, and import of a remotely produced report into a workspace. | S per feature (est.) | Engineers often work through an RMM agent or jump host. The GUI binds 127.0.0.1 only. |

"(est.)" marks an estimate; the research gave no effort for gaps.

**P3 contract shape (proposed).** The Finding fields come from SEC-01; the port key comes from DA-01 and FW-05.

```go
// internal/findings: shared by DA-03, DA-04, DA-06, DA-07, SEC-01, SEC-02
type Finding struct {
    ID          string     // stable rule ID (consumable by pentest-report tooling)
    Severity    string
    Category    string
    Switch      string     // switch identity, not IP
    Port        string     // ifName, not ifIndex (ifIndex renumbers after reboots/stack changes)
    Evidence    []Evidence // OID = value
    Remediation string     // always marked "not applied"
    Assessed    []string   // vendors assessed; others render "not assessed", never "pass"
}
```

Front end: each feature registers an overlay `{id, label, legend, valueFor(port) -> class}`, a port-drawer section and a badge. The Ports faceplate, the Switches list and (later) Topology all render from that registry. Every port annotation is keyed by (switch identity, ifName).

### 3.1 Ranked improvements

| Rank | ID | Improvement | Tier | Value | Effort | Why |
|---|---|---|---|---|---|---|
| 1 | FW-06 | Field SNMP doctor + redacted snmprec capture/replay + sysObjectID quirk KB | quick-win | 5 | M | Explains every failed target on site and grows the real-firmware corpus beyond its one SG300-10 capture |
| 2 | WS-05 | Safe-polling presets (per-device pacing) | quick-win | 4 | S | Spiking a client switch's CPU loses the client; must be in place before real sites |
| 3 | FW-01 | "Where am I plugged in?" card (own-MAC FDB lookup; opt-in passive LLDP/CDP) | quick-win | 5 | M (Method B: S) | First question at every unfamiliar site; the FDB half already exists |
| 4 | FW-04 | Locate view: read-only replug correlation and live MAC/IP/OUI watch | quick-win | 5 | M (replug: S) | "Which port is this jack?" without a toner or a closet trip |
| 5 | WS-01 | Client > Site > Visit workspaces with persistent snapshots | core | 5 | M | Ends per-visit context rebuild; base for diff, reports, allowlists |
| 6 | WS-02 | Per-client credential references (op://, env, prompt), CIDR-scoped, tried in order | core | 5 | M | Prevents credential bleed between clients |
| 7 | WS-03 | Scope guard, network fingerprint, SNMPv3 engine-ID pin, contact log | core | 5 | M | RFC 1918 overlap makes last week's switch list someone else's network; enforces ROE scope |
| 8 | WS-04 | Per-client age encryption, retention, redaction profiles, encrypted hand-over | core | 4 | M | WS-01 makes the laptop a multi-client breach; per-client keys contain a loss |
| 9 | FW-03 | Table warm-up and dwell sampling (freshness labels, MAC-flap detection) | quick-win | 5 | M (warm-up: S) | One on-site pass; missing idle printers and cameras means an incomplete deliverable |
| 10 | OUT-01 | Self-contained HTML report, workbook, offline viewer, provenance | core | 5 | M | A visit isn't finished until something is left behind |
| 11 | FW-02 | Seed-and-crawl discovery via LLDP/CDP management addresses | core | 5 | M | Accurate switch inventories are rare at unfamiliar clients |
| 12 | DA-04 | Port health problem list (counters, errors, duplex/speed, reboot, TCN) | core | 5 | M (duplex: S) | Most calls are "slow/drops", not "map it" |
| 13 | SEC-01 | Observational L2/management-plane findings engine with OID evidence | core | 5 | M (Cisco set ~L) | One pass yields documentation plus an assessment |
| 14 | DA-01 | Visit-to-visit diff, stable device identity, per-MAC timeline | core | 5 | M | "What changed since I was last here?" |
| 15 | DA-08 | ENTITY-MIB inventory, stack-true faceplates, LAG member resolution | core | 5 | M | A faceplate that doesn't match the stack is useless; serials for RMA/EoL |
| 16 | DA-07 | Free and idle port finder, capacity per switch and member | quick-win | 4 | S | "Where can I patch this?"; capacity line in the report |
| 17 | DA-03 | Behind-the-port inference (unmanaged switch, AP, phone+PC, hypervisor, NAT) | quick-win | 4 | S (+M for STP signal) | Labels desk switches and travel routers that placement already isolates |
| 18 | DA-06 | VLAN membership, VLAN matrix, both-end mismatch checks | core | 4 | M | Wrong VLAN or VLAN not on trunk are top on-site faults |
| 19 | DA-05 | PoE per port and PSE budget with correct group.port mapping | core | 4 | M | Unpowered phones, APs and cameras are common tickets; readable remotely |
| 20 | FW-05 | Cable-plant records (jack - panel - port) and label export | core | 4 | M | SNMP can't see the patch layer; a cable schedule is a standard deliverable |
| 21 | OUT-02 | Topology view, editable diagram export, evidence-typed edges | core | 4 | M | Clients and the next engineer read diagrams, not 2,000-row tables |
| 22 | DA-02 | Per-client device policy: SLAP-aware MAC classes, allowlist/watch list | core | 4 | M | Per-client memory of "normal"; CIS 1.1/1.2 evidence |
| 23 | DA-09 | Endpoint identity enrichment (LLDP-MED, CDP extras, multi-source names) | core | 4 | M (MED/CDP columns: S) | Names and models make the map usable offline |
| 24 | SEC-02 | 802.1X/MAB enforcement matrix and NAC-readiness planner | strategic | 4 | L | "We have NAC" becomes jack-level evidence; billable readiness work |
| 25 | PL-01 | Read-only controller/API sources (Meraki, UniFi, Cisco WLC) | strategic | 4 | L | Meraki MS has no BRIDGE/Q-BRIDGE over SNMP (verified; "no FDB" inferred); most endpoints are on Wi-Fi |
| 26 | OUT-03 | NetBox drift and import files; later opt-in reviewed pushes | strategic | 4 | L | Re-entering each visit into the client's documentation system is a hidden cost |
| 27 | DA-11 | DHCP-snooping bindings and IPv6 neighbour fallbacks as IP sources | maybe-later | 3 | S | MAC-to-IP where the router or firewall isn't accessible; Cisco-only |
| 28 | PL-02 | Leave-behind watch mode (10 min to 24 h) | maybe-later | 3 | M | Catches intermittent faults the engineer can't wait on site for |
| 29 | DA-10 | Full spanning-tree view | maybe-later | 3 | M | Loop-hunting depth; the cheap STP scalars are already in DA-04 |
| 30 | DA-12 | SFP/optical DOM diagnostics | maybe-later | 3 | L | Remote fibre levels; vendor scaling differs |

## 4. Detail: top 12

### 4.1 FW-06: Field SNMP doctor, capture/replay and quirk KB (rank 1)

**What.** Three linked pieces:
1. **Staged diagnosis per target.** Each failed step comes with the exact config fix to hand to the client. The stages are:
   1. reachability;
   2. SNMPv3 engine discovery;
   3. credential failure, classified from the Report varbind;
   4. v2c timeout, explained as "wrong community or ACL (the two can't be told apart)";
   5. MIB coverage probe;
   6. Cisco per-VLAN context test.
2. **Capture and replay.** `-record` writes everything walked to a redacted, LibreNMS-compatible snmprec file. `-replay` runs the full mapper offline against that file.
3. **Quirk KB.** Quirks learned at run time (GETBULK broken, a max-repetitions limit, per-VLAN needed) are kept globally, keyed only by sysObjectID, with no host data.

**Why it matters across clients.** With 30 minutes on site, "no MACs found" with no explanation is the worst outcome. A redacted capture from each visit grows the real-firmware regression corpus, which today holds one switch (README, Limitations), and lets bugs be reproduced after leaving the site. What is learned at client A speeds up client B without carrying any of A's data. This is the input for P4.

**Implementation (Go).**
- `internal/snmpc` parses Report PDUs and maps the varbind OID to a cause:

  | OID | Counter | Cause shown |
  |---|---|---|
  | 1.3.6.1.6.3.15.1.1.1 | usmStatsUnsupportedSecLevels | Security level not available for this user |
  | .2 | NotInTimeWindows | Time window, re-sync |
  | .3 | UnknownUserNames | Unknown user |
  | .4 | UnknownEngineIDs | Engine ID mismatch |
  | .5 | WrongDigests | Wrong auth key or protocol |
  | .6 | DecryptionErrors | Wrong priv key or protocol |

- Correction (2026-10-27): gosnmp v1.47.0 exports eleven sentinels (`marshal.go`: `ErrUnknownUsername`, `ErrWrongDigest`, `ErrDecryption`, `ErrUnknownSecurityLevel`, `ErrNotInTimeWindow`, …), not only `ErrUnknownUsername`. They reach the caller only for Reports gosnmp can authenticate: during discovery, on noAuthNoPriv sessions, and for the authenticated Reports some agents send (notInTimeWindow always; unsupportedSecLevels from snmpsim). After discovery gosnmp checks every reply's HMAC before it parses the PDU, so the unauthenticated Report an agent sends for a wrong user, auth key or auth protocol, or privacy key or protocol, is discarded unread and the caller gets only "incoming packet is not authentic, discarding" (verified on snmpsim: wrong user, wrong auth key, MD5 instead of SHA, AES against a DES user and a wrong DES key all gave that string; the dropped datagram carried .3, .5, .5, .6 and .6). The Report varbind therefore cannot be read through gosnmp's request API.
- **Done (2026-10-27): Report recovery and error classes.** `internal/snmpc` wraps an SNMPv3 session's socket after `Connect` with a `net.Conn` that is deliberately not a `net.PacketConn` (gosnmp then uses `Read`/`Write`), keeps the last datagram received since the last send, and, only for the "not authentic" error and after gosnmp's sentinels, decodes it with a scratch noAuthNoPriv `GoSNMP` (`SnmpDecodePacket` skips the HMAC check) and maps the usmStats OID above to a cause. It is a diagnosis, never data: anyone on the path could forge an unauthenticated Report. No extra packets are sent. `snmpc.Kind` (reported as `error_kind`, with a `hint`) also separates no answer before SNMPv3 discovery from no answer after it (wrong credentials on agents that drop them silently), ICMP port unreachable, and error-status refusals (`authorizationError`/`noAccess`, which is how the SG300 rejects noAuthNoPriv for an authPriv group: a Response, not a usmStatsUnsupportedSecLevels Report). First contact goes out once before any retries, so wrong credentials cost one authentication failure on the agent. Still open here: snmpsim e2e cases (wrong user, wrong auth key, AES against a DES user) asserting distinct messages, and the staged doctor below.
- WS-03's plan to preset AuthoritativeEngineID (§4.7) puts every Report through the HMAC check from the first request, so it depends on the same socket tap.
- Decode snmpEngineID (1.3.6.1.6.3.10.2.1.1.0) using the RFC 3411 format bit and enterprise number, and map it to a vendor through the embedded PEN DB.
- Coverage probe: one GETNEXT per root (BRIDGE, Q-BRIDGE, LLDP, LLDP-V2, CDP, ENTITY, POWER-ETHERNET, ARP).
- Fix text comes from templates, for example `snmp-server group NAME v3 priv context vlan- match prefix`.
- Capture: a tee in the snmpc layer writing `numeric OID|type code|value`. Redaction rules:
  - MACs are mapped 1:1 and consistently, because LibreNMS warns "do not break the data".
  - Communities are dropped.
  - sysContact and sysLocation are optionally dropped.
- Replay: a fake transport behind the snmpc interface. The e2e tests load captures next to the snmpsim fixtures.
- Quirk KB: `kb/quirks.json` `{sysObjectID -> quirk}`, used automatically by WS-05.
- Read-only: GET, GETNEXT and GETBULK only.

**GUI.**
- Switches view: a per-switch "Diagnose" button that opens a red/amber/green step list with copy-paste fixes.
- Scan view: a "Record capture" toggle.
- Workspace view (M2): the list of captures.

**Risks.**
- Captures are client-confidential; share them only under the client agreement.
- Redaction must stay consistent within a capture.
- Replay freezes counters, so DA-04 deltas can't be replayed.
- The quirk KB must never record hosts or IPs, or it becomes a cross-client leak.
- Until WS-04 lands, captures have no encrypted home (§7 Q1).

**Sources.** [LibreNMS test units](https://docs.librenms.org/Developing/os/Test-Units/) · [RFC 3414](https://www.rfc-editor.org/rfc/rfc3414) · [usmStats (oidref)](https://oidref.com/1.3.6.1.6.3.15.1.1) · [gosnmp v1.47.0 v3.go](https://raw.githubusercontent.com/gosnmp/gosnmp/v1.47.0/v3.go) · [SolarWinds ETS Switch Port Mapper](https://documentation.solarwinds.com/en/success_center/ets-desk/content/tools/switch-port-mapper.htm) · [Lansweeper community](https://community.lansweeper.com/t5/general-discussions/cisco-switch-port-mapping/td-p/34558) · [LibreNMS FortiSwitch FDB](https://community.librenms.org/t/fortiswitch-fetching-fdb-table/23676)

### 4.2 WS-05: Safe-polling presets (rank 2)

**What.** Per-device pacing:
- one request in flight per device;
- max-repetitions of 10 in Normal, or 5 with a 50 ms delay between PDUs in Gentle;
- a PDU cap per device;
- adaptive backoff;
- abort after N consecutive timeouts, recorded as partial (exit 3);
- Cisco per-VLAN walks serialised.

The preset is chosen per site and remembered once WS-01 exists. FW-06 quirks are applied automatically.

**Why it matters across clients.** Causing a CPU spike or an outage is the fastest way to lose a client. Cisco documents high CPU while being polled. Extreme documents slow, CPU-heavy walks of time-filtered tables (dot1qVlanCurrent, LLDP). Old and SMB switches vary widely.

**Implementation (Go).**
- A per-device limiter wrapped around the snmpc session: either `golang.org/x/time/rate` or a stdlib ticker. The ticker avoids a new dependency (inferred).
- gosnmp exposes MaxRepetitions, Timeout and Retries, but no rate limit.
- Expose the preset in `engine.Request` and the Scan form, and record it in the report's methods section (OUT-01).
- Fold in the time-boxing gap: per-switch progress and ETA, a scan budget per profile, and an explicit policy for keeping partial results. Resuming after laptop sleep or a Wi-Fi drop is not designed yet.
- Read-only.

**GUI.**
- Scan view: a "Polling" selector (Normal / Gentle / Custom).
- Switches view: a per-switch override and a per-switch ETA.

**Risks.**
- The values are guesses until validated on real firmware, so start conservative.
- Gentle mode lengthens Cisco per-VLAN scans considerably; show the ETA.

**Sources.** [Cisco SNMP troubleshooting](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/217632-troubleshoot-snmp-basic-functionality.html) · [Extreme time-filtered walks](https://community.extremenetworks.com/t5/faqs/dfe-s-snmp-mib-walk-runs-slow-when-encountering-timefiltered/m-p/43941) · [gosnmp](https://pkg.go.dev/github.com/gosnmp/gosnmp)

### 4.3 FW-01: "Where am I plugged in?" card (rank 3)

**What.** A card that names the switch, port, port description, VLAN and voice VLAN of the laptop's own link. It uses two methods and flags any disagreement between them. The result seeds FW-02.

**Why it matters across clients.** This is the first question on every unfamiliar site, and the field testers (LinkRunner, Netool, PortFinder) all lead with it. Using both methods is more robust than either alone:
- NetAlly's own guide says its nearest-switch result comes from the SNMP forwarding table;
- LLDP is off by default on Cisco IOS;
- reviewers report weak LLDP on Ubiquiti.

**Implementation (Go), new package `internal/linkid`.**
- **Method B (ship first, S; no privileges; every OS).**
  - Read the active NIC MACs with `net.Interfaces()`.
  - Do a targeted GET of `dot1qTpFdbPort.<fid>.<mac>` (1.3.6.1.2.1.17.7.1.2.2.1.2) or `dot1dTpFdbPort.<mac>` (1.3.6.1.2.1.17.4.3.1.2), or reuse the full walk. Both OIDs are already in `oids.go` (verified).
  - Resolve the port through the existing placement engine.
  - Show the MAC count on that port: more than 1 means a desk switch or phone pass-through.
  - Compare the OS link speed and duplex with the switch's ifHighSpeed.
- **Method A (opt-in; elevated; passive).**
  - Capture: Linux AF_PACKET via `mdlayher/packet` (CAP_NET_RAW), macOS `/dev/bpf`.
  - Filter: EtherType 0x88CC to 01:80:C2:00:00:0E, and SNAP to 01:00:0C:CC:CC:CC.
  - Decode with the pure-Go `gopacket/layers` LinkLayerDiscovery and CiscoDiscovery (Decode8021/8023/DecodeMedia for PVID, MAC/PHY and voice policy).
  - Listen up to 65 s (CDP default 60 s, LLDP 30 s), and stop early once both are heard.
  - Optionally record passive evidence for SEC-01: 802.1Q-tagged frames, DTP/VTP SNAP PIDs and STP BPDUs on the engineer's own port (PID values unverified).
- **Windows.** Npcap is required. Its free licence allows up to 5 systems and no redistribution (verified), so don't bundle it; offer Method B only unless Npcap is already installed. The purego gopacket fork needs a newer Go and has one maintainer, so pin/vendor it or skip it.
- CLI: `atlas-portmap here [-i IFACE] [-listen 65s] [-o json]`. It sends no frames and no SETs.

**GUI.**
- A "Here" card at the top of the Scan view, for example `core-sw Gi1/0/14 "Desk 3B" | VLAN 20 (voice 110) | via SNMP-FDB + LLDP`.
- "Map from here" and "Discover from here" buttons.
- The port is highlighted on the Ports faceplate.

**Risks.**
- Method B needs SNMP access to the access switch.
- Capture needs root or admin.
- Wi-Fi and docks filter link-local multicast.
- An unmanaged switch can forward the upstream switch's LLDP, so Method A names a port one hop away. Method B's MAC count exposes this (inferred).
- Behind an IP phone, the phone can appear as the nearest switch, so show which protocol answered.

**Sources.** [LinkRunner 10G guide](https://assets.testequity.com/te1/Documents/pdf/netally/NetAlly_LinkRunner-10G-User-Guide-v2.4-English_0424.pdf) · [LinkRunner AT 4000 data sheet](https://assets.testequity.com/te1/Documents/pdf/netally/NetAlly_LRAT-4000-Data-Sheet_0524.pdf) · [PeerSpot LinkRunner review](https://origin.peerspot.com/questions/what-needs-improvement-with-linkrunner) · [PortFinder](https://www.wingetly.io/apps/packet-thrower/port-finder) · [LLDP on Cisco](https://ipcisco.com/neighbour-discovery-protocols-part-6-lldp-cisco-configuration/) · [Cisco SMB CDP](https://www.cisco.com/c/en/us/support/docs/smb/switches/cisco-350-series-managed-switches/smb5835-configure-cdp-settings-on-a-switch-through-cli.html) · [gopacket/layers](https://pkg.go.dev/github.com/google/gopacket/layers) · [Npcap](https://npcap.com/)

### 4.4 FW-04: Locate view (replug correlation and watch) (rank 4)

**What.**
- (a) **Replug.** Snapshot ifOperStatus and ifLastChange on the selected switches, ask the engineer to unplug and replug the cable, poll every 1-2 s, and highlight the ports that transitioned.
- (b) **Watch.** Poll FDB and ARP for a MAC, IP or OUI, and notify when and where it appears.
- (c) **Assign jack label.** Record the answer in the cable plant (FW-05).

**Why it matters across clients.** "Which switch port is this wall jack or device on?" is the most common field request. This answers it from the laptop, read-only, without a toner or a closet trip, and saves the answer into the client's documentation.

**Implementation (Go).**
- Each cycle, GETBULK ifOperStatus (1.3.6.1.2.1.2.2.1.8, already collected) and ifLastChange (1.3.6.1.2.1.2.2.1.9, new) on the selected switches only. That is about 2 PDUs per 48 ports, through the existing gosnmp sessions and under WS-05 limits.
- A changed ifLastChange, or a down/up transition, marks the candidate port.
- Watch: a targeted GET of `dot1qTpFdbPort.<fid>.<mac>` when the FID is known; otherwise column walks of the Q-BRIDGE/BRIDGE FDB and router ARP every N s.
- Alerts use a browser Notification plus a sound.
- Annotation record: `{switch identity, ifName, jack, panel, room, note, captured_by, time}`.
- Replug alone is S effort.
- Read-only. The unplug is the engineer's physical action; the tool sends no SET.

**GUI.**
- A new "Locate" view with Replug and Watch tabs and a large live port grid that flashes on transitions.
- An "Assign to jack..." action on any port in the Ports faceplate.

**Risks.**
- Unplugging interrupts the endpoint.
- PoE devices that stay up, and err-disabled or admin-down ports, show no transition.
- Some old agents rate-limit SNMP, so the poll interval must be adjustable.
- Watch needs the device to send traffic.

**Sources.** [Patch-panel tracking thread](https://yomotherboard.com/question/what-software-can-track-physical-patch-panel-to-switch-connections/) · [SolarWinds UDT](https://www.solarwinds.com/user-device-tracker) · [Domotz topology](https://help.domotz.com/user-guide/network-topology/) · [RFC 2863](https://www.rfc-editor.org/rfc/rfc2863.txt)

### 4.5 WS-01: Client > Site > Visit workspaces (rank 5)

**What.** A first-class workspace per client. It holds:
- sites (scope CIDRs, seed switches, ARP sources, inventory CSV, scan profiles);
- notes and port annotations;
- a ticket or job reference per visit;
- every scan, as an immutable snapshot.

Exactly one workspace is active, and every scan, export and push is bound to it. The CLI stays stateless by default.

**Why it matters across clients.**
- Rebuilding context at each visit is the main time sink.
- History underpins diff, reports and allowlists.
- Today GUI scans are in memory only (`/api/scans`), and Label is free text (verified, `internal/gui`, `engine.Request`).
- Common commercial port mappers keep one global database with no client boundary.
- CISA tells MSPs to segregate customer data sets.

**Implementation (Go), new package `internal/workspace`.**
- Data root: `os.UserConfigDir()/atlas-portmap`, or a portable `./atlas-portmap-data` when a `portable` marker file sits next to the binary.
- Layout: `workspaces/<uuid>/manifest` plus `snapshots/<RFC3339>_<site>.json.gz`, encrypted per WS-04. Directories are named by UUID so a lost laptop doesn't reveal client names; the client name lives inside the manifest.
- A snapshot is the existing `output.Report` JSON plus provenance: tool version, operator, profile, and the credential-set name per device.
- Sites are seeded through the existing `POST /api/reports` import path and the inventory CSV parser, including SPM's import format.
- Routes become `/api/ws/{id}/scans`. Switching workspace calls `Server.cancelAll`.
- Scan profiles:
  - Find device: targeted.
  - Document: all ports + inventory + dwell.
  - Audit: Document + 802.1X + findings.
- CLI: `ws new|list|use`, `map --ws acme --site hq --save`.
- Inferred: snapshots should carry the identity keys DA-01 needs from the start (snmpEngineID, dot1dBaseBridgeAddress, sysName, ports by ifName). Then later diffs need no re-scan.
- No network effect.

**GUI.**
- A header "Client > Site" switcher with lock state, and a coloured client banner on every view.
- A new Workspace view: sites, notes, visit list, import/export.
- The Scan form is pre-filled from the site.
- Results, Switches and Ports are scoped to the active workspace.

**Risks.**
- Keep the stateless CLI as the default so existing scripts don't break.
- Workspaces hold client-confidential data, so ship WS-04 in the same release (§5).
- Team sync between engineers is not covered.

**Sources.** [SPM details](https://www.switchportmapper.com/moredetails.htm) · [Switch Port Mapper](https://www.switchportmapper.com/) · [CISA AA22-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a) · [Auvik for MSPs](https://www.auvik.com/why-auvik-msp/)

### 4.6 WS-02: Per-client credential references (rank 6)

**What.** Named credential sets whose fields are references, never values: `op://<ClientVault>/<item>/<field>`, `env:NAME` or `prompt`.
- Each set has `applies_to` CIDRs (only/no) and an order.
- The engine tries only the sets whose CIDR covers the target, and caches the name of the set that worked per device.
- Values are resolved just in time, held in memory for the run only, and zeroed afterwards. They are never written to snapshots, logs, errors or API responses.
- SNMPv3 sets must carry CIDRs.

**Why it matters across clients.**
- Credential bleed (client A's community or v3 user tried against client B) is a security incident and a contract problem.
- CISA: "Do not reuse admin credentials across multiple customers."
- Auvik's inherit-and-try-all model shows the failure mode.
- Netdisco's tagged, ACL-scoped `device_auth` with a cached working tag is the proven pattern. Netdisco notes that with several v3 stanzas and no ACLs, only the first is used.

**Implementation (Go), new package `internal/secrets` with a `Resolver` interface.**
- **op provider.** Exec `op read` / `op inject` to resolve a whole set at once. This keeps biometric prompts to one per set and keeps the binary static and CGO-free; the Go SDK's desktop-app auth needs CGO.
- **env provider.** The current `PORTMAP_*` design.
- **prompt provider.** A write-only modal POST.
- When a set is saved, reject any `op://` reference outside the workspace's bound vault.
- Record per device: set name, SNMP version, security level and auth/priv protocol. This feeds the SEC-01 management-plane rules.
- A "Test" button runs RFC 3414 discovery plus a GET of `sysObjectID.0` against one device.
- CLI users keep `op run --env-file site.env -- atlas-portmap ...`.
- Read-only.

**GUI.**
- Workspace > Site settings > Credentials table: name, version, security level, provider badge + vault, applies_to, last-worked count, Test.
- The Scan view shows the chosen set name per target, never the value.

**Risks.**
- `op` with a service account needs the network. Desktop-app integration offline is unverified, so provide a typed-in fallback that is never persisted.
- Trying several sets raises authenticationFailure traps and SIEM alerts. Limit attempts to the credentials the client issued, and log every try.
- The 1Password service-account cap of 100 makes one service account per client unrealistic for large MSPs. Desktop-app auth with a vault per client is the default.

**Sources.** [1Password secret references](https://www.1password.dev/cli/secret-references/) · [1Password service accounts](https://www.1password.dev/service-accounts/) · [onepassword-sdk-go](https://github.com/1Password/onepassword-sdk-go) · [Netdisco configuration](https://github.com/netdisco/netdisco/wiki/Configuration) · [CISA AA22-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a)

### 4.7 WS-03: Scope guard, network fingerprint, engine-ID pin, contact log (rank 7)

**What.** Three checks run before any packet leaves:
1. The target is inside the site's scope CIDRs (re-checked after DNS resolution) and is not on the exclusion list.
2. The current network fingerprint (default-gateway IP and MAC, local prefixes, DNS suffix) matches this site's earlier visits. A match with a different workspace is a hard block.
3. For v3, an unauthenticated RFC 3414 discovery returns the pinned snmpEngineID before any authenticated request is sent.

Also:
- Hosts never seen before are listed for confirmation.
- An engagement record (authoriser, SOW/ticket ref, date window, stop contact, permitted check classes) gates warm-up, crawl and the listener.
- Every device contacted is logged, overrides included.

**Why it matters across clients.**
- RFC 1918 ranges overlap across clients, so last week's switch list can be someone else's network.
- v1/v2c communities travel in cleartext, and SNMPv3 HMACs are crackable offline (hashcat modes 25000-27300). Authenticated traffic sent to the wrong network therefore leaks credentials.
- For pentest work, this enforces rules-of-engagement scope by default. None of the port mappers checked describes such a guard.

**Implementation (Go), new package `internal/scope`.**
- Called in `engine.makePlan` and for every warm-up, crawl and probe target.
- Default gateway: `/proc/net/route` on Linux, `route -n get default` on macOS, `GetIpForwardTable2` on Windows. The gateway MAC comes from `internal/localarp`.
- Fingerprints are stored as `HMAC-SHA256(local key, gatewayMAC)` in a small plaintext index, so locked workspaces can be matched without decrypting them.
- v3 pin:
  - Send an explicit noAuthNoPriv probe with an empty user, read AuthoritativeEngineID from the Report, and compare it with the stored value.
  - gosnmp's `negotiateInitialSecurityParameters` runs its own discovery and accepts `ErrUnknownUsername` if an engine ID is present (verified, v1.47.0 `v3.go`), so preset AuthoritativeEngineID after the pin check.
  - Also store snmpEngineBoots and snmpEngineTime (1.3.6.1.6.3.10.2.1.2 and .3).
- An override requires typing the site name, and is logged.
- The contact log is append-only per visit (UTC, set name, subtrees, PDU count, outcome) and flows into the report.
- Read-only. The pin probe is unauthenticated discovery.

**GUI.**
- A "Site check" pill (green/amber/red) next to the Scan button, with details.
- An engagement/scope banner in the Scan view.
- Out-of-scope targets are rejected inline with the reason.
- An "Audit" tab in the Workspace view.

**Risks.**
- The gateway MAC changes on firewall replacement and in some HA pairs (VRRP 00:00:5e:00:01:xx is stable). A mismatch therefore only warns; only a match to another workspace blocks.
- The engine-ID pin catches mistakes, not a spoofing attacker, because discovery is unauthenticated.
- v2c has no identity check before authentication, so the fingerprint is the only guard there.
- The guard supports authorisation but doesn't replace the client's written scope.

**Sources.** [RFC 3414](https://www.rfc-editor.org/rfc/rfc3414.html) · [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) · [Net-SNMP security tutorial](https://net-snmp.sourceforge.io/wiki/index.php/TUT:Security) · [CISA AA22-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a) · [NIST Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement) · [gosnmp v1.47.0 v3.go](https://raw.githubusercontent.com/gosnmp/gosnmp/v1.47.0/v3.go)

### 4.8 WS-04: Per-client encryption at rest, retention, redaction, hand-over (rank 8)

**What.**
- **Encryption.** Every workspace file is encrypted with age to per-workspace recipients:
  - the engineer's X25519 identity, kept in that client's 1Password vault or the OS keychain;
  - an optional MSP escrow recipient;
  - an optional YubiKey plugin;
  - or an scrypt passphrase on single-user laptops.
- **Auto-lock.** Idle auto-lock clears decrypted data and resolved secrets.
- **Retention.** A retention table per workspace, with crypto-shred at contract end.
- **Redaction profiles:**
  - Internal;
  - Client;
  - Shareable: HMAC'd MACs that keep the OUI, IP host part masked, no ifAlias, no 802.1X usernames.
- **Hand-over.** Encrypted bundles go to a colleague's age or SSH key.

**Why it matters across clients.**
- A field laptop ends up holding dozens of clients' topology, MAC/IP inventories and aliases containing user and room names. Losing it breaches every client at once.
- Per-client keys contain a loss to one client and allow provable deletion.
- SPM states no encryption for its stored groups and credentials.
- MAC/IP-to-person data is personal data (GDPR Recital 30).

**Implementation (Go).**
- New package `internal/store`: JSON, then gzip, then `age.Encrypt` (binary, no armor).
  - Snapshots are immutable, one file per run, so no database is needed.
  - SQLCipher would need CGO and break the static cross-builds.
  - This adds `filippo.io/age` (BSD-3), the first dependency besides gosnmp.
- New package `internal/redact`, applied before output and report rendering. Golden-file tests prove that no raw MAC, IP or username survives the Shareable profile.
- CLI: `ws export --to age1...|--to-ssh key.pub`, `ws import`, `ws shred`.
- Plaintext exports carry a "leaving the encrypted store" warning and a log entry.
- No network effect.

**GUI.**
- An "Unlock" step when a workspace is selected, and a lock icon in the header.
- A Retention panel in workspace settings.
- A redaction preset with a before/after row preview in every export dialog.

**Risks.**
- Losing the key loses the data, so offer an escrow recipient.
- age has no in-place recipient rotation; re-encrypt when recipients change.
- Pseudonymised data is still personal data.
- Plaintext reports already delivered are outside crypto-shred.
- age plugins are installed per OS.
- An unlocked session is not protected, hence auto-lock.

**Sources.** [filippo.io/age](https://pkg.go.dev/filippo.io/age) · [age](https://github.com/FiloSottile/age) · [GDPR Recital 30](https://gdpr-info.eu/recitals/no-30/) · [SPM details](https://www.switchportmapper.com/moredetails.htm) · [CISA AA22-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a)

### 4.9 FW-03: Table warm-up and dwell sampling (rank 9)

**What.**
- **Warm-up.** An opt-in, scoped, rate-limited touch sweep of the in-scope subnets right before mapping. It makes silent devices refill the FDB and router ARP tables.
- **Dwell (optional).** Re-walks only the FDB/ARP tables every agingTime/2 or less for N minutes, and merges first-seen, last-seen and polls-seen per MAC.
- **Freshness labels.** Each entry is labelled "seen passively" or "seen after warm-up".
- **Aging warning.** The tool warns when sweep plus walk time exceeds dot1dTpAgingTime.
- **MAC flapping.** The repeated samples detect the same MAC on two edge ports of one switch and VLAN within the window.

**Why it matters across clients.**
- The engineer usually gets one on-site pass, and a map missing idle printers and cameras is an incomplete deliverable. README: "There is no ping sweep" (verified).
- SolarWinds, OpUtils and SoftPerfect all recommend or build a pre-sweep.
- Flapping MACs point to loops during the same visit.

**Implementation (Go), new package `internal/warmup`.**
- One UDP datagram to port 9 per address via `net.DialUDP`. This is unprivileged on every OS; the laptop or gateway ARPs for the target, and the reply teaches every switch on the path.
- Optional unprivileged ICMP via `golang.org/x/net/icmp` where the OS permits it.
- Defaults:
  - 200 pps hard cap;
  - at most a /22 per run;
  - the address count is shown before starting;
  - every target passes WS-03.
- Engine order: warm-up, then router ARP, then FDB walks in parallel. Read dot1dTpAgingTime (1.3.6.1.2.1.17.4.2.0; 802.1D default 300 s).
- Dwell: `-dwell 20m -dwell-interval 2m`. Placement runs per poll and the results are unioned; only the merged result is stored per visit.
- Flap detection:
  - same MAC on two non-uplink ports in one VLAN within the window;
  - correlated with the delta of dot1dStpTopChanges (1.3.6.1.2.1.17.2.4.0);
  - VRRP 00:00:5e:00:01:xx and HSRP 00:00:0c:07:ac:xx are whitelisted.
- Warm-up is active traffic. Dwell is read-only SNMP.

**GUI.**
- Scan view: a "Warm up subnets" toggle with CIDR chips (from the site scope or router interfaces), a progress bar, and a dwell timer with "stop early, keep results".
- Results: a "Freshness/Seen" column and filter, and a flapping badge on MAC rows.

**Risks.**
- Warm-up is active traffic: keep it inside the authorised scope, tell the client, and expect possible IDS/NAC anomaly alerts.
- It doesn't reach unrouted VLANs, ports held unauthorized by 802.1X, or isolated Wi-Fi clients.
- The Windows neighbour-cache size limit is unverified.
- Roaming docks, VM migration and NIC teaming cause legitimate moves.

**Sources.** [SolarWinds ETS Switch Port Mapper](https://documentation.solarwinds.com/en/success_center/ets-desk/content/tools/switch-port-mapper.htm) · [OpUtils knowledge base](https://www.manageengine.com/products/oputils/swicth-port-mapper-knowledge-base.md) · [SoftPerfect Switch Port Mapper](https://www.softperfect.com/products/portmapper/) · [RFC 4188](https://www.rfc-editor.org/rfc/rfc4188.html) · [Cisco MAC flap troubleshooting](https://www.cisco.com/c/de_de/support/docs/lan-switching/spanning-tree-protocol-stp-8021d/221722-troubleshoot-mac-flaps-loop-on-cisco-cat.html) · [Netdisco configuration](https://github.com/netdisco/netdisco/wiki/Configuration)

### 4.10 OUT-01: One-click client deliverable (rank 10)

**What.** Per visit, the tool generates:
- **One self-contained HTML file**: inline CSS/SVG, no JS needed, and print CSS so any browser saves a clean PDF.
- **Report contents**: client and MSP branding; summary; per-switch faceplates from the GUI's SVG generator; inventory; capacity and unused ports; VLAN matrix; PoE budget; problems and findings; changes since the last visit; cable schedule; notes and photos (EXIF stripped).
- **A methods-and-limits section**: time; tool version and binary sha256; dataset hashes from `SOURCES.txt`; SNMP version and security level per device (no secrets); failed switches; whether warm-up or crawl ran; what wasn't checked.
- **A workbook**: CSV now, XLSX later.
- **Topology exports** (OUT-02).
- **An optional read-only offline viewer.**
- **An optional sha256 manifest** with an Ed25519 signature.

Sections fill in as their source features land. v1 (M2) covers summary, faceplates, inventory, capacity, and methods-and-limits.

**Why it matters across clients.**
- A visit isn't finished until something is left behind; today that means rebuilding spreadsheets after hours.
- OpUtils, UDT and Network Detective sell reports. SPM offers XML and a browser report with no branding.
- Producing the report offline, with no cloud, suits air-gapped and no-internet sites.

**Implementation (Go), new package `internal/report`.**
- `html/template` plus `go:embed` CSS; `@page` A4 or Letter by workspace locale; a page break per switch; a classification banner ("CONFIDENTIAL - <client>").
- CSV goes through `internal/output`'s formula-injection-safe writer.
- Viewer: bundle `internal/gui/web/js` into one inline script, inject the snapshot, and set a CSP meta of `default-src 'none'` (plus inline script/style and `data:` images) so it cannot phone home.
- XLSX: excelize needs Go 1.26.0 or later (verified), while `go.mod` declares go 1.24.0 (verified), and vulnerability advisories were listed for the version checked. Either bump the toolchain and pin, or write minimal XLSX with `archive/zip` + `encoding/xml`.
- Avoid `go-pdf/fpdf` (archived) and headless Chrome (breaks the static binary).
- Signing: `crypto/sha256` + `crypto/ed25519` from the stdlib, with a `report verify` subcommand.
- WS-04 redaction is applied before rendering.
- No network effect.

**GUI.**
- A "Report" button on Results and History opens a Report view: visit picker, section toggles, redaction preset, branding from workspace settings, live preview iframe, and Save HTML / Save viewer / Export pack.
- "Add note/photo" on the Switch and Port drawers.

**Risks.**
- Once exported, the report is plaintext client data: stamp a classification, offer redaction, and log the export.
- Print fidelity varies by browser; test Chrome, Edge and Firefox.
- Word "unused" as "down >= X days", with the evidence.
- Framework references mean "evidence toward", not attestation.
- List coverage gaps: FDB aging, unreadable VLANs, failed switches.

**Sources.** [OpUtils Switch Port Mapper](https://www.manageengine.com/products/oputils/switch-port-mapper.html) · [Switch Port Mapper](https://www.switchportmapper.com/) · [Network Detective](https://www.rapidfiretools.com/products/network-detective/) · [Domotz MSP onboarding checklist](https://blog.domotz.com/think-like-msp/msp-onboarding-checklist-documenting-client-networks/) · [Patch-panel labeling](https://ampcom.com/blogs/industry-insights/patch-panel-port-numbering-labeling-system) · [excelize](https://github.com/qax-os/excelize) · [go-pdf/fpdf](https://github.com/go-pdf/fpdf) · [LinkRunner AT 3000 data sheet](https://cdn.shopify.com/s/files/1/1362/8711/files/LRAT_3000_Data_Sheet.pdf)

### 4.11 FW-02: Seed-and-crawl discovery (rank 11)

**What.** Discovery starts from seeds: the FW-01 result, the default gateway or a given IP. From there it:
1. reads each switch's neighbour management addresses;
2. keeps neighbours with bridge or router capability (phones and APs are skipped by default);
3. applies workspace scope and walks breadth-first with a depth limit;
4. de-duplicates by snmpEngineID, dot1dBaseBridgeAddress and sysName;
5. tries the matching WS-02 credential sets.

The engineer approves the candidate list before mapping. An optional, rate-limited CIDR probe uses SNMPv3 engine discovery, which sends no credentials. A v2c probe runs only when the profile explicitly allows it.

**Why it matters across clients.**
- At an unfamiliar client the engineer rarely has an accurate switch inventory; an MSP quoted 15-40 hours to draw a medium client's network.
- Netdisco's `discover_neighbors` is the proven pattern.
- Today the tool cannot crawl: no management address in `collect.Neighbor`, and neither lldpRemManAddr nor cdpCacheAddress in `oids.go` (verified).

**Implementation (Go).**
- **LLDP.** Walk lldpRemManAddrIfSubtype (1.0.8802.1.1.2.1.4.2.1.3), a readable column. The address is in the index (timeMark.localPortNum.remIndex.addrSubtype.len.addr; IANA subtype 1 = IPv4, 2 = IPv6), so decode it from the OID suffix as OpenL2M does.
- **CDP**, under 1.3.6.1.4.1.9.9.23.1.2.1.1 (verified): cdpCacheAddressType .3, cdpCacheAddress .4, cdpCachePrimaryMgmtAddrType .19, cdpCachePrimaryMgmtAddr .20.
- Add `ManagementAddrs` to `collect.Neighbor`.
- Read the LLDP-V2-MIB tree (1.3.111.2.802.1.1.13) in the same change; README lists it as not read.
- New package `internal/discover`:
  - BFS with max hops (default 4);
  - discover_only/no lists;
  - skip phones and APs based on lldpRemSysCapEnabled and cdpCacheCapabilities;
  - a concurrency cap and a per-host timeout;
  - every target passes WS-03.
- CLI: `-crawl -seed auto|IP -max-hops N -scope CIDR,...`.
- The SNMP reads are read-only. The probe is unauthenticated v3 discovery, plus v2c only when the profile opts in.

**GUI.**
- Scan view: a "Discover" mode with a seed field and a live candidate table, then "Map selected". Columns: IP, sysName, vendor from the sysObjectID PEN, found via (LLDP/CDP/probe), credential set, reason (reachable / auth-fail / out-of-scope), checkbox.
- Switches view: advertised-but-unreachable neighbours.

**Risks.**
- Advertised management addresses may be out-of-band, loopback or blocked by ACLs; mark them "advertised, unreachable".
- A v2c probe sends the community in cleartext to every address, so it stays opt-in.
- Failed authentication attempts raise traps and SIEM alerts, so tell the client's NOC first.
- LLDP neighbours can include carrier CPE or another tenant's gear, so the scope guard is mandatory.

**Sources.** [Netdisco configuration](https://github.com/netdisco/netdisco/wiki/Configuration) · [NetBox orb-agent SNMP discovery](https://netboxlabs.com/docs/orb-agent/backends/snmp_discovery) · [LLDP-MIB (Observium)](https://mibs.observium.org/mib/LLDP-MIB/) · [CDP cache table (oidref)](https://oidref.com/1.3.6.1.4.1.9.9.23.1.2.1.1) · [OpenL2M LLDP discovery](https://openl2m.readthedocs.io/code/drivers/snmp/snmp-discover-lldp.html) · [RFC 3414](https://www.rfc-editor.org/rfc/rfc3414) · [Auvik client onboarding](https://www.auvik.com/franklyit/blog/client-onboarding/)

### 4.12 DA-04: Port health and problem list (rank 12)

**What.** Two counter samples N seconds apart: default 30 s, 0 = off, and a single sample gives errors since the counter reset.
- **Per port:** in/out utilisation as % of ifHighSpeed, error and discard rates, and FCS / alignment / late-collision deltas.
- **Flags:**
  - duplex or speed mismatch on both ends of identified links;
  - half duplex on any up port;
  - edge ports at 10/100 where the device class implies gigabit;
  - uptime under 24 h;
  - a recent STP topology change;
  - duplicate IPs across ARP sources (VRRP/HSRP MACs excluded).
- Each problem carries severity, raw values and per-site thresholds, and is worded as a symptom, not a root cause.

**Why it matters across clients.**
- Field calls are usually "slow / drops / won't connect", not "map the network". One screen ranking the bad ports beats the map when time on site is short.
- atlas-portmap reads none of these counters today (verified, `oids.go`).
- Domotz, SolarWinds and EtherScope sell exactly this.

**Implementation (Go), new package `internal/health`.**

| Group | Objects |
|---|---|
| IF-MIB | ifHCInOctets 1.3.6.1.2.1.31.1.1.1.6, ifHCOutOctets .10, ifCounterDiscontinuityTime .19; ifInDiscards 1.3.6.1.2.1.2.2.1.13, ifInErrors .14, ifOutDiscards .19, ifOutErrors .20 |
| EtherLike (1.3.6.1.2.1.10.7.2.1) | dot3StatsAlignmentErrors .2, FCSErrors .3, LateCollisions .8, DuplexStatus .19 (unknown 1, half 2, full 3) |
| Far end | the neighbour's own dot3StatsDuplexStatus if it is mapped; otherwise cdpCacheDuplex 1.3.6.1.4.1.9.9.23.1.2.1.1.12, or lldpXdot3RemPortAutoNegEnabled 1.0.8802.1.1.2.1.5.4623.1.3.1.1.2 / OperMauType .4 decoded with an embedded IANA-MAU table |
| Scalars | sysUpTime 1.3.6.1.2.1.1.3.0, dot1dStpTimeSinceTopologyChange 1.3.6.1.2.1.17.2.3.0, dot1dStpTopChanges .2.4.0, dot1dStpDesignatedRoot .2.5.0 |

- Discard a delta if ifCounterDiscontinuityTime changed or sysUpTime went backwards. Handle Counter32 wrap on v1.
- Report unknown duplex separately: Netdisco's `<>` join silently drops NULLs.
- Output a `problems[]` array in JSON, using the P3 Finding model.
- Ship duplex mismatch first (S), as the first consumer of the P3 contract.
- Read-only. Don't copy competitors' port-bounce or PoE-cycle writes.

**GUI.**
- Ports faceplate modes: status / utilisation / errors / speed-duplex heatmap.
- A port drawer with raw counters, deltas and the rule that fired.
- Problems in the shared Findings view, sortable by severity, with red/amber badges in the Switches list (and highlighted edges in Topology once OUT-02 lands).

**Risks.**
- Two samples give a snapshot, not peak load.
- Some agents update counters only periodically, so short intervals can read 0 (inferred).
- Thresholds are environment-specific; the defaults are suggestions.
- Extra walks load old CPUs (use WS-05).
- Late collisions alone can mean bad cabling.

**Sources.** [RFC 2863](https://www.rfc-editor.org/rfc/rfc2863.txt) · [RFC 3635](https://www.rfc-editor.org/rfc/rfc3635.txt) · [SolarWinds duplex mismatch](https://documentation.solarwinds.com/en/success_center/npm/content/core-detecting-possible-duplex-mismatches.htm) · [Netdisco DuplexMismatch](https://raw.githubusercontent.com/netdisco/netdisco/master/lib/App/Netdisco/DB/Result/Virtual/DuplexMismatch.pm) · [dot3StatsEntry (oidref)](https://oidref.com/1.3.6.1.2.1.10.7.2.1) · [lldpXdot3RemPortEntry (oidref)](https://oidref.com/1.0.8802.1.1.2.1.5.4623.1.3.1.1) · [EtherScope nXG](https://netcor.de/download.php?file=2485) · [RFC 4188](https://www.rfc-editor.org/rfc/rfc4188.txt)

## 5. Sequencing

### M1: Field-safe on real switches

**Outcome:**
- An engineer can run atlas-portmap at a real client without risking switch load.
- Every failed target gets a diagnosis and a client-ready fix.
- The engineer can answer "where am I plugged in?" and "which port is this jack?".
- The engineer brings home a redacted capture that becomes a replay test.
- The GUI extension contract is proven by real overlays.

**Contents:**
- P1, P2, P3, P5 (Windows signing at minimum)
- WS-05, FW-06
- FW-01 Method B (Method A deferred to M2)
- FW-04 replug tab
- DA-07
- DA-03 without the STP-designated-bridge signal
- DA-04 duplex-mismatch slice

**Exit criteria (proposed):**
- e2e replay tests pass on captures from the first lab vendors (§7 Q3).
- Vendor support matrix v1 is published from the corpus.
- No target in a real run ends without a doctor verdict.

**Dependency:** where captures are stored before WS-04 exists (§7 Q1).

### M2: Client-separated, scoped and deliverable

**Outcome:**
- Every scan belongs to one client workspace.
- Credentials resolve only from that client's references, and only for in-scope CIDRs.
- No packet leaves without the scope and fingerprint check.
- Client data is age-encrypted at rest.
- The map is complete (warm-up and dwell) and discoverable from a seed.
- The engineer leaves an offline HTML report with a methods-and-limits section.

**Contents:**
- WS-01 + WS-04 (same release), WS-02, WS-03
- FW-03, FW-02
- OUT-01 v1 (summary, faceplates, inventory, capacity, methods-and-limits, CSV)
- FW-04 watch tab, FW-01 Method A
- P6 headless parity for `ws`, warm-up, crawl and report

**Exit criteria (proposed):**
- A disk image of a laptop with workspaces contains no plaintext client name, MAC, IP or credential.
- A scan whose fingerprint matches another workspace is blocked.
- Shareable-redaction golden tests pass.

### M3: Return-visit and assessment value

**Outcome:**
- On a return visit the engineer opens the client and sees what changed, a ranked problem list and evidence-backed L2 findings.
- The report adds stack-true faceplates, asset register, VLAN matrix, PoE budget, topology diagram and cable schedule.

**Contents:**
- DA-01, DA-04 (full), SEC-01 (generic rules first, then the Cisco set)
- DA-08, DA-06, DA-05 (collector)
- OUT-02, FW-05
- DA-02
- DA-09 if capacity allows

**Exit criteria (proposed):**
- Placement and behind-port accuracy are measured against ground truth: ports confirmed by FW-04 replug and stored as labels in the capture corpus. This addresses the accuracy-measurement gap.

**Beyond M3 (unscheduled):** SEC-02, PL-01, OUT-03, DA-11, PL-02, DA-10, DA-12 (see §6).

### GUI views by milestone

| Milestone | Existing views extended | New views or surfaces |
|---|---|---|
| M1 | Scan: Here card, Polling selector. Switches: Diagnose, ETA, capacity bar. Ports: idle overlay, behind-port badge, duplex overlay. | Locate (Replug), minimal Findings list (P3) |
| M2 | Header: Client > Site switcher, lock, client banner. Scan: Site-check pill, Discover mode, warm-up/dwell, Record toggle. Results: Freshness column, flap badge. | Workspace (sites, credentials, captures, Audit), Report, Locate (Watch) |
| M3 | Ports: stack panels, VLAN/PoE/health/changes overlays. Switches: entity tree, PoE gauge, VLAN matrix sub-tab. Results: Trust column, Name with source. | History, Findings (full), Topology, Cabling |

## 6. Deferred and rejected

### 6.1 Deferred (not rejected)

| Item | Reason | Revisit when |
|---|---|---|
| SEC-02 802.1X/MAB matrix (L) | Needs the SEC-01 engine and DA-06 first. IBNS 2.0 visibility in the CAF tables is unverified. Hardened SNMP views often exclude .9.9.656. Usernames are personal data. | After M3. Ship the IEEE8021-PAE path first, then Cisco CAF. |
| PL-01 Meraki/UniFi/WLC (L) | Meraki is cloud-only, which breaks the offline promise. The UniFi API is undocumented and changes across releases. Meraki keys are org-scoped. | When the client base includes Meraki or UniFi sites (§7 Q9). |
| OUT-03 NetBox/IT Glue/Hudu (L) | Phase 2 writes into the client's system of record (outward-facing). Phase 1 depends on DA-01's renderer. | Phase 1 after DA-01; phase 2 only on a client request. |
| DA-11 DHCP snooping / IPv6 ND fallbacks (S) | Cisco-only. Bindings are reported unavailable on some IOS-XE 16.x releases. | Pull into M3 if MACs without IPs turn out to be common in the field. |
| PL-02 leave-behind watch | Needs explicit consent, physical security and a removal date. Credentials are held for the whole run. | After M2 (needs WS-02 and WS-04). |
| DA-10 full STP view | The cheap scalars are already in DA-04. MSTP is not covered. | When loop hunting needs per-VLAN or per-port depth. |
| DA-12 SFP DOM (L) | Vendor scaling differs. Some platforms need DOM monitoring enabled, which the tool must not change. | After DA-08 (sensor-to-port mapping depends on it). |
| SPM SQLite history import | SPM's schema was not researched. | Only if there are SPM users to migrate. |
| Team workspace sync/merge | WS-04 bundles cover one-way hand-over only. | §7 Q11. |

### 6.2 Rejected

| Item | Reason |
|---|---|
| ROE-gated default-community check and any built-in pentest mode | This is credential guessing, not mapping. A read with a guessed community is unauthorised access (18 USC 1030(a)(2)(C), CMA s.1) unless the client's written authorisation names the check. It also trips lockouts and SIEM alerts. Dedicated tools (onesixtyone, nmap snmp-brute) exist. SEC-01 reports SNMP posture observationally. |
| 802.1X/MAB bypass, voice-VLAN hopping, DTP negotiation from the laptop | Active attacks, out of scope for a read-only mapper. Kept passively: DTP/VTP/BPDU observation (FW-01 Method A) and the read-only DTP/native-VLAN findings in SEC-01. |
| Own-link AutoTest, including active DHCPDISCOVER rogue-DHCP probing and multi-VLAN tagging | Scope creep. Needs raw sockets and admin rights, may conflict with the Windows DHCP client on UDP 68, and can trip DHCP snooping or port security. Only the OS-vs-ifHighSpeed comparison is kept (FW-01). |
| Port-locate beacons (NIC link toggling, LED bursts) | NIC flapping can err-disable the client's port (Cisco SMB link-flap prevention at 3 flaps per second), forces 802.1X re-auth and sends linkDown traps to the client's NOC. FW-04 answers the same question read-only. |
| PSA CI sync and ticket-note posting | Duplicates RMM-to-PSA sync, risking duplicate CIs. The endpoints were not verified. The ticket reference is kept as visit metadata (WS-01). |
| Offline CISA KEV matching | KEV has no version ranges, so every Cisco or Aruba switch would be flagged: noise in a client deliverable. Export the DA-08 asset register to proper vulnerability tooling instead. |
| IT Glue / Hudu / Bitwarden as credential providers | An IT Glue key with Password Access reads passwords across all organisations, which defeats per-client segregation. Hudu behaviour is unverified. |
| Hash-chained audit log anchored in PSA notes, SSHSIG signatures | Over-engineered for a laptop-local log. The WS-03 contact log and the OUT-01 Ed25519 manifest cover the need. |
| Standalone compliance evidence pack | "Evidence toward" only, and the ISO wording came from secondary sources. Kept as an optional reference column on SEC-01 findings. |
| Native VSDX writer | L effort. draw.io round-trips VSDX. |
| SQLite/SQLCipher history store | SQLCipher needs CGO and breaks the static cross-builds. Encrypted JSON snapshots suffice. Add a `modernc.org/sqlite` index only if history queries become slow. |
| NetBox Diode SDK | Needs a newer Go than `go.mod` and pulls in gRPC. REST and CSV cover the same ground. |
| Default-on or unscoped v1/v2c probe sweeps | Sends the community in cleartext to every address. FW-02 keeps only v3 engine discovery, or an opt-in scoped v2c probe. |
| Printer-specific label templates | Per-printer maintenance burden. A CSV merge file plus an HTML sheet is the portable contract (FW-05). |
| Cisco MAC-notification history as the flap source | Populated only if MAC notification is configured, and the tool must not configure it. FW-03 dwell works on every vendor. |

## 7. Open questions

| # | Decision | Options | Recommendation |
|---|---|---|---|
| Q1 | Capture storage in M1, before WS-04 exists | (a) Pull `filippo.io/age` forward and encrypt captures to the engineer's recipient. (b) Allow `-record` only in the lab until M2. (c) Plaintext redacted captures. | (a). WS-04 adds the same dependency anyway; (c) leaves client data in plaintext. |
| Q2 | May redacted client captures enter the repo's regression corpus? | (a) Never; only lab captures go in the repo. (b) With explicit client consent per capture. | (a) by default, (b) case by case. Client contracts decide. |
| Q3 | Lab hardware and vendor order for P4 | The research list: Catalyst 9200/2960-X, Aruba CX 6100, HPE OfficeConnect/1920, Juniper EX2300, UniFi, TP-Link Omada, Netgear smart, FortiSwitch. Plus SMB smart switches (D-Link, Zyxel). | Order by your actual client base. Include at least one SMB smart switch, since SMB is the least researched area. |
| Q4 | Windows passive capture (FW-01 Method A) | (a) Method B only unless the user already has Npcap. (b) Npcap OEM licence (cost not researched). (c) Drop Method A on Windows. | (a). |
| Q5 | Dependency policy | `filippo.io/age` (WS-04); `x/time/rate` or stdlib ticker (WS-05); `gopacket/layers` + `mdlayher/packet` (FW-01); Go 1.26 toolchain bump for excelize, or hand-written XLSX (OUT-01). | Accept age; stdlib ticker; upstream `gopacket/layers` (not the purego fork); hand-written XLSX unless the toolchain bump is wanted for other reasons. |
| Q6 | Key custody for WS-04 | Engineer identity per client in that client's 1Password vault, or in the OS keychain. MSP escrow recipient yes/no. YubiKey plugin yes/no. | 1Password per client (matches the WS-02 vault binding) plus one offline escrow recipient. Offline unlock through the desktop app is unverified; test it first. |
| Q7 | Offline credential fallback | Typed-in values for the run only, never persisted; or refuse to scan without 1Password. | Typed-in fallback. Sites without internet are part of the persona. |
| Q8 | Active-traffic gate (FW-03 warm-up, FW-02 probe, FW-01 listener) | Require an engagement record that permits active checks; or a per-scan confirmation only. Defaults: 200 pps, at most /22. | Require the engagement record. Keep the researched defaults until real firmware data says otherwise. |
| Q9 | Cloud/API sources (PL-01) | In scope (it breaks the offline promise for those sources), or out of scope. | Decide from client mix. If in scope, label cloud-sourced rows clearly. |
| Q10 | Writes to client systems (OUT-03 phase 2) | Never; or opt-in with plan review and client approval each time. | Report and import files only until a client asks for writes. |
| Q11 | Single engineer or a team sharing clients? | Solo (WS-04 bundles suffice), or team (needs sync/merge and an authoritative-visit rule). | Assume solo for M1-M3. A team requirement changes the WS-01 design. |
| Q12 | IPv6 requirement | SNMP over IPv6 transport, IPv6-only LLDP management addresses (subtype 2), dual-stack scope CIDRs: required in M2 or later? | Include in the WS-03 and FW-02 design in M2. Every lens left it untested. |
| Q13 | Signing identities (P5) | Get an Authenticode certificate and an Apple Developer ID now, or ship unsigned with an allow-listing note. | Get them before the first client site. Unsigned scanners get blocked. |
| Q14 | Report branding | Whose MSP branding and classification wording goes on OUT-01. | Your call. Needed before OUT-01 v1. |