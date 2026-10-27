// Switches view: one card per switch with what was read and anything that went wrong.
import { h, svgIcon, plural } from '../dom.js';
import { state, update } from '../store.js';
import { noReport, pageHead, reportSubtitle, portKey, uplinkKind, switchKey, summaryKey, sub } from './common.js';

// Pill text per error_kind (snmpc.Kind). Reports from before error_kind existed say 'failed'.
// No prototype: an imported report's error_kind can be any string ('constructor' included).
const KIND_LABEL = Object.assign(Object.create(null), {
  'no-response': 'no response', 'v3-no-response': 'no response', 'port-closed': 'port closed',
  'auth-failed': 'auth failed', 'unknown-user': 'auth failed', 'wrong-digest': 'auth failed', decryption: 'auth failed',
  'security-level': 'auth failed', 'time-window': 'auth failed', 'access-denied': 'access denied', cancelled: 'cancelled',
});

function failLabel(s) {
  return KIND_LABEL[s.error_kind] || 'failed';
}

/** What went wrong: the hint (what to check) leads, the raw error is folded away beneath it. */
function problem(s, lead) {
  return h('div', null,
    lead ? h('div', null, lead) : null,
    h('div', null, s.hint || s.error),
    s.hint ? h('details', null, h('summary', null, 'Error details'), h('div', { class: 'mono' }, s.error)) : null);
}

function counts(r, key) {
  const rows = (r.entries || []).filter(e => switchKey(e) === key);
  const ports = new Map();
  for (const e of rows) ports.set(portKey(e), e);
  const up = [...ports.values()].filter(e => e.port_status === 'up').length;
  return {
    ports: ports.size,
    up,
    endpoints: rows.filter(e => e.mac && !e.secondary).length,
    uplinks: new Set(rows.filter(e => uplinkKind(e) === 'switch').map(portKey)).size,
  };
}

function card(r, s, i) {
  const key = summaryKey(r, s, i);
  const c = counts(r, key);
  const name = s.name || s.target;
  const status = s.partial ? h('span', { class: 'pill warn', title: failLabel(s) }, 'partial')
    : s.error ? h('span', { class: 'pill danger' }, failLabel(s))
    : (s.warnings || []).length ? h('span', { class: 'pill warn' }, plural(s.warnings.length, 'warning'))
      : h('span', { class: 'pill ok' }, 'ok');
  const body = h('div', { class: 'card-body' },
    h('div', { class: 'sw-title' }, svgIcon('switch', 20), h('span', { class: 'name' }, name), status),
    h('div', { class: 'mono muted' }, s.target),
    s.vendor || s.description ? h('div', null, s.vendor ? h('div', null, s.vendor) : null, s.description ? h('div', { class: 'sw-descr', title: s.description }, s.description) : null) : null,
    h('div', { class: 'sw-meta' },
      s.fdb_source ? h('span', { class: 'pill accent plain' }, `FDB: ${s.fdb_source}`) : null,
      h('span', { class: `pill plain ${s.lldp ? 'ok' : 'idle'}` }, s.lldp ? 'LLDP' : 'no LLDP'),
      h('span', { class: 'pill plain' }, `${s.fdb_rows || 0} FDB rows`)),
    h('div', { class: 'sw-nums' },
      h('div', null, h('b', null, String(c.endpoints)), h('span', null, 'endpoints')),
      h('div', null, h('b', null, String(c.ports)), h('span', null, 'ports seen')),
      h('div', null, h('b', null, String(c.up)), h('span', null, 'ports up')),
      h('div', null, h('b', null, String(c.uplinks)), h('span', null, 'uplinks'))),
    s.error ? h('div', { class: s.partial ? 'callout' : 'callout danger' }, svgIcon('alert', 16),
      problem(s, s.partial ? 'Stopped part-way: what was read is shown, but this switch’s rows are incomplete.' : '')) : null,
    (s.warnings || []).length ? h('div', { class: 'callout' }, svgIcon('alert', 16), h('ul', null, s.warnings.map(w => h('li', null, w)))) : null,
    s.error && !s.partial ? null : h('div', { class: 'row' },
      h('a', { class: 'btn', href: '#/ports' }, svgIcon('ports'), 'Ports'),
      h('button', { class: 'btn', onclick: () => { update({ filters: { ...state.filters, sw: key, port: '', q: '' } }); location.hash = '#/results'; } }, svgIcon('list'), 'Devices')));
  return h('section', { class: 'card sw-card' }, body);
}

export function render(main) {
  const r = state.report;
  const page = h('div', { class: 'page stack' });
  main.append(page);
  if (!r) {
    page.append(noReport());
    return;
  }
  page.append(pageHead('Switches', reportSubtitle(r)));
  page.append(h('div', { class: 'cards' }, (r.switches || []).map((s, i) => card(r, s, i))));
  const sources = r.arp_sources || [];
  page.append(h('section', { class: 'card' },
    h('div', { class: 'card-head' }, svgIcon('router', 18), 'ARP sources', h('span', { class: 'sub' }, 'where IP addresses came from')),
    sources.length ? h('table', { class: 'data' },
      h('thead', null, h('tr', null, h('th', null, 'Source'), h('th', null, 'Entries'), h('th', null, 'Result'))),
      h('tbody', null, sources.map(s => h('tr', null,
        h('td', { class: 'mono' }, s.target), h('td', null, String(s.entries)),
        h('td', null, s.error ? [h('span', { class: 'pill danger', title: s.error }, failLabel(s)), sub(s.hint || s.error),
          s.hint ? h('details', null, h('summary', null, 'Error details'), h('div', { class: 'mono' }, s.error)) : null]
          : h('span', { class: 'pill ok' }, 'ok'))))))
      : h('div', { class: 'card-body muted' }, 'No ARP sources were queried, so endpoints have no IP addresses.')));
  for (const w of r.warnings || []) page.append(h('div', { class: 'callout' }, svgIcon('alert', 16), w));
}
