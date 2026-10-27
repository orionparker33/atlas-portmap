// Results view: the port map as a searchable, sortable table with a details drawer.
import { h, append, svgIcon, clear, toast, debounce, plural } from '../dom.js';
import { state, update } from '../store.js';
import { exportCurrent, endpoints, devices } from '../actions.js';
import { naturalCompare } from '../natural.js';
import { noReport, statusPill, sub, pageHead, reportSubtitle, copy, portKey, uplinkKind, switchKey, summaryKey, keyActivate } from './common.js';

const PAGE = 1500;

const COLUMNS = [
  { key: 'switch', label: 'Switch', get: e => e.switch, cell: e => [e.switch, sub(e.switch_addr)] },
  { key: 'port', label: 'Port', get: e => e.port, cell: e => [h('span', { class: 'mono' }, e.port), sub(e.port_alias)] },
  { key: 'vlan', label: 'VLAN', get: e => e.vlan || 0, num: true, cell: e => (e.vlan ? [String(e.vlan), sub(e.vlan_name)] : '') },
  { key: 'mac', label: 'MAC', get: e => e.mac || '', cell: e => h('span', { class: 'mono' }, e.mac || '') },
  { key: 'vendor', label: 'Vendor', get: e => e.vendor || '', cell: e => e.vendor || '' },
  { key: 'ip', label: 'IP address', get: e => (e.ips || [])[0] || '', cell: ipCell },
  { key: 'host', label: 'Hostname', optional: r => r.entries.some(e => (e.hostnames || []).length), get: e => (e.hostnames || [])[0] || '', cell: e => (e.hostnames || []).join(', ') },
  { key: 'status', label: 'Status', get: e => e.port_status || '', cell: e => statusPill(e.port_status) },
  { key: 'dot1x', label: '802.1X', optional: r => r.entries.some(e => e.dot1x), get: e => e.dot1x || '', cell: e => e.dot1x || '' },
  { key: 'note', label: 'Note', get: e => (e.switch_mac ? 'switch ' : '') + (e.uplink ? 'uplink ' : '') + (e.neighbor || ''), cell: noteCell },
];

// The row's own addresses, then (muted) any of this MAC's addresses that belong to another VLAN
// or could not be tied to one: a router on a trunk answers on several VLANs with one MAC.
function ipCell(e) {
  const own = (e.ips || []).map((ip, i) => (i ? [h('br'), ip] : ip));
  const other = (e.other_ips || []).map(ip => h('span', { class: 'sub', title: 'This MAC’s address in another VLAN, or one no source tied to a VLAN' }, ip)); // .sub is a block: no <br>
  return h('span', { class: 'mono' }, own, other);
}

function portModeText(e) {
  if (e.port_mode === 'trunk') return `tagged ${e.tagged_vlans || '-'}${e.native_vlan ? `; native ${e.native_vlan}` : ''}`;
  if (e.port_mode === 'hybrid') return `untagged ${e.untagged_vlans || '-'}${e.tagged_vlans ? `; tagged ${e.tagged_vlans}` : ''}${e.native_vlan ? `; native ${e.native_vlan}` : ''}`;
  return e.port_mode || '';
}

function noteCell(e) {
  const out = [];
  if (!e.mac) out.push(h('span', { class: 'muted' }, e.macs_on_port ? `${plural(e.macs_on_port, 'MAC')}, placed elsewhere` : 'no devices'));
  if (e.secondary) out.push(h('span', { class: 'pill idle plain' }, 'secondary sighting'));
  if (e.switch_mac) out.push(h('span', { class: 'pill uplink plain', title: 'This MAC is the switch’s own address (bridge or management MAC)' }, `switch ${e.switch_mac}`));
  if (e.port_mode === 'trunk' || e.port_mode === 'hybrid') out.push(h('span', { class: 'pill accent plain', title: portModeText(e) }, e.port_mode));
  const kind = uplinkKind(e);
  if (kind === 'switch') out.push(h('span', { class: 'pill uplink', title: e.uplink_reason || '' }, 'uplink'));
  else if (kind === 'shared') out.push(h('span', { class: 'pill warn', title: e.uplink_reason || '' }, 'shared port'));
  if (e.neighbor) out.push(h('span', { class: 'sub', title: e.neighbor }, e.neighbor.length > 70 ? e.neighbor.slice(0, 69) + '…' : e.neighbor));
  return out;
}

function haystack(e) {
  return [e.switch, e.switch_addr, e.port, e.port_alias, e.vlan, e.vlan_name, e.mac, (e.mac || '').replace(/[^0-9a-f]/gi, ''),
    e.vendor, ...(e.ips || []), ...(e.other_ips || []), ...(e.hostnames || []), e.neighbor, e.uplink_reason, e.dot1x, e.port_mode, e.switch_mac,
    ...Object.values(e.extra || {})]
    .filter(x => x !== undefined && x !== null && x !== '').join(' ').toLowerCase();
}

function filtered(r) {
  const f = state.filters;
  const terms = f.q.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = (r.entries || []).filter(e => {
    if (!f.showEmpty && !e.mac) return false;
    if (f.hideUplinks && uplinkKind(e) === 'switch') return false;
    if (f.sw && switchKey(e) !== f.sw) return false;
    if (f.vlan && String(e.vlan || '') !== f.vlan) return false;
    if (f.port && e.port !== f.port) return false;
    if (terms.length) {
      const hs = e._hs || (e._hs = haystack(e));
      if (!terms.every(t => hs.includes(t))) return false;
    }
    return true;
  });
  const col = COLUMNS.find(c => c.key === state.sort.key) || COLUMNS[0];
  const dir = state.sort.dir;
  const order = r.switches.map((s, i) => summaryKey(r, s, i));
  rows.sort((a, b) => {
    let c;
    if (col.key === 'switch') c = order.indexOf(switchKey(a)) - order.indexOf(switchKey(b)) || naturalCompare(a.port, b.port);
    else if (col.num) c = col.get(a) - col.get(b);
    else c = naturalCompare(col.get(a), col.get(b));
    return dir * (c || naturalCompare(a.port, b.port) || naturalCompare(a.mac, b.mac));
  });
  return rows;
}

function stats(r) {
  const eps = endpoints(r);
  const devs = devices(r);
  const ports = new Set(eps.map(portKey));
  const uplinks = new Set((r.entries || []).filter(e => uplinkKind(e) === 'switch').map(portKey));
  const failed = r.switches.filter(s => s.error && !s.partial).length;
  const partial = r.switches.filter(s => s.error && s.partial).length;
  const warnings = r.switches.reduce((n, s) => n + (s.warnings || []).length, 0) + (r.warnings || []).length;
  const withIP = devs.filter(rows => rows.some(e => (e.ips || []).length || (e.other_ips || []).length)).length;
  const tile = (k, v, s) => h('div', { class: 'card stat' }, h('div', { class: 'k' }, k), h('div', { class: 'v' }, String(v)), h('div', { class: 's' }, s));
  return h('div', { class: 'stats' },
    tile('Devices', devs.length, `${withIP} with an IP address`),
    tile('Ports in use', ports.size, `${uplinks.size} uplink ${uplinks.size === 1 ? 'port' : 'ports'}`),
    tile('Switches', r.switches.length, failed || partial ? [failed ? `${failed} failed` : '', partial ? `${partial} partial` : ''].filter(Boolean).join(', ') : 'all answered'),
    tile('VLANs', new Set(eps.map(e => e.vlan).filter(Boolean)).size, 'with endpoints'),
    tile('Warnings', warnings, warnings ? 'see Switches' : 'none'));
}

function drawer(e, onClose) {
  const kv = h('dl', { class: 'kv' });
  const row = (k, v) => {
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) return;
    kv.append(h('dt', null, k), h('dd', null, Array.isArray(v) ? v.join(', ') : String(v)));
  };
  row('Switch', `${e.switch} (${e.switch_addr})`);
  row('Port', e.port);
  row('Description', e.port_alias);
  row('Status', e.port_status);
  row('Speed', e.speed_mbps ? `${e.speed_mbps} Mb/s` : '');
  row('ifIndex', e.if_index);
  row('Bridge port', e.bridge_port);
  row('VLAN', e.vlan ? `${e.vlan}${e.vlan_name ? ` (${e.vlan_name})` : ''}` : '');
  row('VLAN from', { fdb: 'forwarding table', port: 'port configuration (access VLAN)', pvid: 'port PVID (a guess: tagged traffic shows the native VLAN)', 'fdb-other-switch': 'another switch’s forwarding table' }[e.vlan_source] || '');
  row('Port mode', e.port_mode ? `${e.port_mode}${e.port_mode === 'access' ? '' : `: ${portModeText(e)}`}` : '');
  row('LAG member of', e.member_of);
  row('MAC address', e.mac);
  row('Vendor', e.vendor);
  row('MAC of switch', e.switch_mac);
  row('IP addresses', e.ips);
  row('Other addresses of this MAC', e.other_ips);
  row('Hostnames', e.hostnames);
  row('MACs on port', e.macs_on_port);
  row(uplinkKind(e) === 'shared' ? 'Shared port' : 'Uplink', e.uplink ? e.uplink_reason || 'yes' : '');
  row('Neighbour', e.neighbor);
  row('802.1X', e.dot1x);
  for (const [k, v] of Object.entries(e.extra || {})) row(k, v);
  row('Also seen on', e.also_seen);
  if (e.secondary) row('Sighting', 'secondary (not this MAC’s best location)');
  const back = h('div', { class: 'drawer-backdrop', onclick: onClose });
  const panel = h('aside', { class: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Port details' },
    h('div', { class: 'drawer-head' }, svgIcon(e.mac ? 'ports' : 'switch', 18), h('h3', null, e.mac || `${e.switch} ${e.port}`),
      h('button', { class: 'btn btn-ghost btn-icon', 'aria-label': 'Close', onclick: onClose }, svgIcon('close'))),
    h('div', { class: 'drawer-body' },
      h('div', { class: 'kv-actions' },
        e.mac ? h('button', { class: 'btn', onclick: () => copy(e.mac) }, svgIcon('copy'), 'Copy MAC') : null,
        (e.ips || [])[0] ? h('button', { class: 'btn', onclick: () => copy(e.ips[0]) }, svgIcon('copy'), 'Copy IP') : null,
        h('button', { class: 'btn', onclick: () => { update({ filters: { ...state.filters, sw: switchKey(e), port: e.port, q: '', showEmpty: true } }); onClose(); window.dispatchEvent(new HashChangeEvent('hashchange')); } }, svgIcon('ports'), 'All devices on this port')),
      kv));
  return [back, panel];
}

let paintAll = () => {};

export function render(main) {
  const r = state.report;
  const page = h('div', { class: 'page' });
  main.append(page);
  if (!r) {
    page.append(noReport());
    return;
  }
  r.switches = r.switches || [];
  r.entries = r.entries || [];
  const cols = COLUMNS.filter(c => !c.optional || c.optional(r));
  const tableBox = h('div', { class: 'table-wrap' });
  const count = h('span', { class: 'count' });
  const chips = h('div', { class: 'row' });
  let limit = PAGE;
  let selected = null;
  let open = null;

  const closeDrawer = () => {
    if (open) open.forEach(n => n.remove());
    open = null;
    selected = null;
    paint();
  };
  const onKey = e => { if (e.key === 'Escape' && open) closeDrawer(); };
  document.addEventListener('keydown', onKey);

  function paint() {
    const rows = filtered(r);
    const total = endpoints(r).length;
    count.textContent = `${rows.length} of ${total} endpoints${rows.length > limit ? ` (showing ${limit})` : ''}`;
    clear(chips);
    if (state.filters.port) {
      const si = r.switches.findIndex((s, i) => summaryKey(r, s, i) === state.filters.sw);
      const swName = si >= 0 ? (r.switches[si].name || r.switches[si].target) : '';
      chips.append(h('span', { class: 'chip' }, `Port ${swName} ${state.filters.port}`,
        h('button', { 'aria-label': 'Clear port filter', onclick: () => { update({ filters: { ...state.filters, port: '' } }); paint(); } }, svgIcon('close', 13))));
    }
    const thead = h('tr', null, cols.map(c => {
      const active = state.sort.key === c.key;
      const th = h('th', { class: 'sortable', scope: 'col', 'aria-sort': active ? (state.sort.dir > 0 ? 'ascending' : 'descending') : 'none' },
        c.label, active ? h('span', { class: 'dir', 'aria-hidden': 'true' }, state.sort.dir > 0 ? '▲' : '▼') : null);
      return keyActivate(th, () => { update({ sort: { key: c.key, dir: active ? -state.sort.dir : 1 } }); paint(); });
    }));
    const tbody = h('tbody');
    for (const e of rows.slice(0, limit)) {
      const tr = h('tr', { class: e === selected ? 'sel' : '', 'aria-label': `${e.switch} ${e.port} ${e.mac || ''}`.trim() },
        cols.map(c => h('td', { class: c.key === 'mac' || c.key === 'port' ? 'nowrap' : '' }, c.cell(e))));
      keyActivate(tr, () => {
        selected = e;
        if (open) open.forEach(n => n.remove());
        open = drawer(e, closeDrawer);
        document.body.append(...open);
        open[1].querySelector('button')?.focus();
        for (const x of tbody.querySelectorAll('tr.sel')) x.classList.remove('sel');
        tr.classList.add('sel');
      });
      tbody.append(tr);
    }
    const table = h('table', { class: 'data' }, h('thead', null, thead), tbody);
    clear(tableBox).append(table);
    if (!rows.length) tableBox.append(h('div', { class: 'empty' }, h('p', null, 'No rows match the filters.')));
    if (rows.length > limit) {
      tableBox.append(h('div', { class: 'more' }, h('button', { class: 'btn', onclick: () => { limit = rows.length; paint(); } }, `Show all ${rows.length} rows`)));
    }
  }
  paintAll = paint;

  const f = state.filters;
  const search = h('input', { class: 'input', id: 'search', type: 'search', placeholder: 'Search MAC, IP, vendor, port, VLAN…  ( / )', value: f.q, 'aria-label': 'Search' });
  search.addEventListener('input', debounce(() => { update({ filters: { ...state.filters, q: search.value } }); limit = PAGE; paint(); }, 120));

  const vlans = [...new Set(endpoints(r).map(e => e.vlan).filter(Boolean))].sort((a, b) => a - b);
  const names = r.switches.map(s => s.name || s.target);
  const swSel = h('select', { class: 'select', 'aria-label': 'Switch', value: f.sw, onchange: e => { update({ filters: { ...state.filters, sw: e.target.value, port: '' } }); paint(); } },
    h('option', { value: '' }, 'All switches'),
    r.switches.map((s, i) => h('option', { value: summaryKey(r, s, i) }, names.filter(n => n === names[i]).length > 1 ? `${names[i]} (${s.target})` : names[i])));
  const vlanSel = h('select', { class: 'select', 'aria-label': 'VLAN', value: f.vlan, onchange: e => { update({ filters: { ...state.filters, vlan: e.target.value } }); paint(); } },
    h('option', { value: '' }, 'All VLANs'), vlans.map(v => h('option', { value: String(v) }, `VLAN ${v}`)));
  const tog = (key, label) => h('label', { class: 'check' },
    h('input', { type: 'checkbox', checked: !!f[key], onchange: e => { update({ filters: { ...state.filters, [key]: e.target.checked } }); paint(); } }),
    h('span', { class: 't' }, label));

  const warn = [];
  const failed = r.switches.filter(s => s.error && !s.partial);
  const partial = r.switches.filter(s => s.error && s.partial);
  if (failed.length) {
    warn.push(h('div', { class: 'callout danger' }, svgIcon('alert', 16),
      h('div', null, `${plural(failed.length, 'switch', 'switches')} failed and returned no data: `, failed.map(s => s.target).join(', '), '. See Switches for details.')));
  }
  if (partial.length) {
    warn.push(h('div', { class: 'callout' }, svgIcon('alert', 16),
      h('div', null, `${plural(partial.length, 'switch', 'switches')} stopped part-way, so the rows from ${partial.length === 1 ? 'it are' : 'them are'} incomplete: `,
        partial.map(s => (s.name && s.name !== s.target ? `${s.name} (${s.target})` : s.target)).join(', '), '. See Switches for details.')));
  }
  for (const w of r.warnings || []) warn.push(h('div', { class: 'callout' }, svgIcon('alert', 16), w));

  append(page, [
    pageHead('Results', reportSubtitle(r),
      h('button', { class: 'btn', onclick: () => exportCurrent('csv').catch(e => toast(e.message, 'error')) }, svgIcon('save'), 'Export CSV'),
      h('button', { class: 'btn', onclick: () => exportCurrent('json').catch(e => toast(e.message, 'error')) }, svgIcon('save'), 'Save JSON')),
    stats(r),
    warn.length ? h('div', { class: 'stack warnings' }, warn) : null,
    h('section', { class: 'card' },
      h('div', { class: 'toolbar' },
        h('div', { class: 'search' }, svgIcon('search'), search),
        swSel, vlanSel, tog('hideUplinks', 'Hide uplink ports'), tog('showEmpty', 'Show ports without devices'), chips, count),
      tableBox)]);
  paint();
  return () => {
    document.removeEventListener('keydown', onKey);
    if (open) open.forEach(n => n.remove());
    paintAll = () => {};
  };
}
