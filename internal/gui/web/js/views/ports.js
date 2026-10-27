// Ports view: each switch drawn as a faceplate, one tile per port, coloured by what is on it.
import { h, svgIcon, plural } from '../dom.js';
import { state, update } from '../store.js';
import { naturalCompare } from '../natural.js';
import { noReport, pageHead, reportSubtitle, portKey, uplinkKind, switchKey, summaryKey, splitPort } from './common.js';

const LEGEND = [['active', 'Devices'], ['shared', 'Shared (bridge / many MACs)'], ['uplink', 'Uplink to a switch'], ['idle', 'Up, no devices'], ['down', 'Down'], ['disabled', 'Disabled'], ['trunk', '802.1Q trunk']];

function portModel(rows) {
  const ports = new Map();
  for (const e of rows) {
    const k = portKey(e);
    let p = ports.get(k);
    if (!p) {
      p = { label: e.port, alias: e.port_alias, status: e.port_status, macs: e.macs_on_port || 0, uplink: false, shared: false, reason: '', neighbor: e.neighbor, member: e.member_of || '', mode: e.port_mode || '', tagged: e.tagged_vlans || '', untagged: e.untagged_vlans || '', native: e.native_vlan || 0, vlan: e.vlan_source === 'port' ? e.vlan : 0, devices: [], byMac: new Map() };
      ports.set(k, p);
    }
    p.macs = Math.max(p.macs, e.macs_on_port || 0);
    const uk = uplinkKind(e);
    if (uk) {
      p.uplink = p.uplink || uk === 'switch';
      p.shared = p.shared || uk === 'shared';
      p.reason = e.uplink_reason || p.reason;
    }
    if (e.mac && !e.secondary) {
      // One device per MAC: a router on a trunk has a row per VLAN.
      let d = p.byMac.get(e.mac);
      if (d) d.rows.push(e);
      else {
        d = { mac: e.mac, vendor: e.vendor, sw: e.switch_mac || '', rows: [e] };
        p.byMac.set(e.mac, d);
        p.devices.push(d);
      }
    }
  }
  // A LAG member takes its aggregate's uplink/shared state.
  const byLabel = new Map([...ports.values()].map(p => [p.label, p]));
  for (const p of ports.values()) {
    const agg = p.member && byLabel.get(p.member);
    if (agg && !p.uplink && !p.shared) {
      p.uplink = agg.uplink;
      p.shared = agg.shared;
      p.reason = p.reason || (agg.reason ? `${p.member}: ${agg.reason}` : '');
    }
  }
  return [...ports.values()].sort((a, b) => naturalCompare(a.label, b.label));
}

function kind(p) {
  if (p.status === 'disabled') return 'disabled';
  if (p.uplink) return 'uplink';
  if (p.shared) return 'shared';
  if (p.devices.length) return 'active';
  if (p.status === 'up') return 'idle';
  return 'down';
}

function tile(swKey, p) {
  const [, n] = splitPort(p.label);
  const mode = p.mode === 'trunk' ? ` · trunk: tagged ${p.tagged}${p.native ? `, native ${p.native}` : ''}`
    : p.mode === 'hybrid' ? ` · hybrid: untagged ${p.untagged}${p.tagged ? `, tagged ${p.tagged}` : ''}` : p.vlan ? ` · VLAN ${p.vlan}` : '';
  const lines = [`${p.label}${p.alias ? ` — ${p.alias}` : ''}${p.member ? ` (member of ${p.member})` : ''}`, `${p.status || 'status unknown'}${mode}${p.uplink ? ` · uplink (${p.reason})` : p.shared ? ` · shared port (${p.reason})` : ''}`];
  for (const d of p.devices.slice(0, 8)) {
    const ips = d.rows.length > 1 ? d.rows.map(e => `VLAN ${e.vlan}: ${(e.ips || []).join(', ') || '-'}`).join(' · ') : (d.rows[0].ips || []).join(', ');
    const other = [...new Set(d.rows.flatMap(e => e.other_ips || []))].join(', ');
    lines.push(`${d.mac}  ${d.vendor || ''}  ${ips}${other ? `${ips ? ' · ' : ''}also ${other}` : ''}${d.sw ? ` (switch ${d.sw})` : ''}`.trim());
  }
  if (p.devices.length > 8) lines.push(`… ${p.devices.length - 8} more`);
  if (p.neighbor) lines.push(p.neighbor);
  return h('button', {
    class: `port port--${kind(p)}${p.mode === 'trunk' ? ' is-trunk' : ''}`, type: 'button', title: lines.join('\n'),
    'aria-label': `${p.label}: ${p.devices.length ? plural(p.devices.length, 'device') : kind(p)}`,
    onclick: () => {
      update({ filters: { ...state.filters, sw: swKey, port: p.label, q: '', showEmpty: true, hideUplinks: false } });
      location.hash = '#/results';
    },
  }, h('span', { class: 'led' }), h('span', { class: 'n' }, n.length > 6 ? n.slice(-6) : n), p.devices.length ? h('span', { class: 'c' }, String(p.devices.length)) : null);
}

export function render(main) {
  const r = state.report;
  const page = h('div', { class: 'page stack' });
  main.append(page);
  if (!r) {
    page.append(noReport());
    return;
  }
  const hasEmpty = (r.entries || []).some(e => !e.mac);
  page.append(pageHead('Ports', reportSubtitle(r),
    h('div', { class: 'legend' }, LEGEND.map(([k, label]) => h('span', null, h('i', { class: k }), label)))));
  if (!hasEmpty) {
    page.append(h('div', { class: 'callout info' }, svgIcon('alert', 16),
      'This report only lists ports with devices on them. Scan with “All ports” (or -all-ports) to see free and down ports too.'));
  }
  (r.switches || []).forEach((s, si) => {
    const name = s.name || s.target;
    const key = summaryKey(r, s, si);
    const rows = (r.entries || []).filter(e => switchKey(e) === key);
    const ports = portModel(rows);
    const groups = new Map();
    for (const p of ports) {
      const [prefix] = splitPort(p.label);
      if (!groups.has(prefix)) groups.set(prefix, []);
      groups.get(prefix).push(p);
    }
    const up = ports.filter(p => p.status === 'up').length;
    const used = ports.filter(p => p.devices.length).length;
    const body = h('div', { class: 'card-body faceplate' });
    if (s.error) body.append(h('div', { class: 'callout danger' }, svgIcon('alert', 16), s.error));
    else if (!ports.length) body.append(h('div', { class: 'muted' }, 'No ports reported.'));
    for (const [prefix, list] of groups) {
      body.append(h('div', null, h('div', { class: 'port-group-label' }, prefix.trim() || 'ports'), h('div', { class: 'port-grid' }, list.map(p => tile(key, p)))));
    }
    page.append(h('section', { class: 'card sw-section' },
      h('div', { class: 'card-head' }, svgIcon('switch', 18), name, h('span', { class: 'sub mono' }, s.target),
        h('div', { class: 'end muted' }, `${plural(ports.length, 'port')} · ${up} up · ${used} with devices`)),
      body));
  });
}
