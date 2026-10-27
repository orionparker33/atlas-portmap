// Scan view: targets, credentials, options, and live progress for the running scan.
import { h, svgIcon, clear, toast, fmtMs, plural } from '../dom.js';
import { state, subscribe } from '../store.js';
import { startScan, cancelScan } from '../actions.js';
import { pageHead } from './common.js';

const DEFAULTS = {
  label: '', switches: '', arp: '', inventory: '', inventoryName: '',
  snmp: { version: '2c', community: '', port: 161, timeout_ms: 3000, retries: 1, max_reps: 25, v3_user: '', v3_auth_proto: 'sha', v3_auth_pass: '', v3_priv_proto: 'aes', v3_priv_pass: '', v3_context: '' },
  options: { cisco_per_vlan: 'auto', vlans: '', lldp: true, cdp: true, dot1x: false, columns: '', uplink_threshold: 10, all_sightings: false, all_ports: true, resolve: false, arp_from_switches: true, local_arp: false, concurrency: 8, mac_format: 'colon' },
};

function form() {
  if (!state.form) state.form = structuredClone(DEFAULTS);
  return state.form;
}

// ---- small bound controls ----

function field(label, control, hint) {
  const target = control.matches('input,select,textarea') ? control : control.querySelector('input,select,textarea');
  const id = target.id || (target.id = `f-${Math.random().toString(36).slice(2, 9)}`);
  return h('div', { class: 'field' }, h('label', { for: id }, label), control, hint ? h('span', { class: 'hint' }, hint) : null);
}

function text(obj, key, attrs = {}) {
  return h('input', { class: 'input', value: obj[key] ?? '', ...attrs, oninput: e => { obj[key] = e.target.value; } });
}

function num(obj, key, attrs = {}) {
  return h('input', { class: 'input', type: 'number', value: String(obj[key]), ...attrs, oninput: e => { obj[key] = e.target.value === '' ? 0 : Number(e.target.value); } });
}

function area(obj, key, attrs = {}) {
  return h('textarea', { class: 'textarea', spellcheck: 'false', value: obj[key] ?? '', ...attrs, oninput: e => { obj[key] = e.target.value; } });
}

function select(obj, key, options, attrs = {}) {
  return h('select', { class: 'select', value: obj[key], ...attrs, onchange: e => { obj[key] = e.target.value; } },
    options.map(([v, label]) => h('option', { value: v }, label)));
}

function secret(obj, key, attrs = {}) {
  const input = h('input', { class: 'input', type: 'password', autocomplete: 'off', spellcheck: 'false', value: obj[key] ?? '', ...attrs, oninput: e => { obj[key] = e.target.value; } });
  const eye = h('button', {
    class: 'btn btn-ghost btn-icon', type: 'button', 'aria-label': 'Show or hide',
    onclick: () => { input.type = input.type === 'password' ? 'text' : 'password'; },
  }, svgIcon('eye'));
  return h('div', { class: 'input-wrap' }, input, eye);
}

function toggle(obj, key, title, desc) {
  return h('label', { class: 'check' },
    h('input', { type: 'checkbox', checked: !!obj[key], onchange: e => { obj[key] = e.target.checked; } }),
    h('span', null, h('span', { class: 't' }, title), desc ? h('span', { class: 'd' }, desc) : null));
}

// ---- cards ----

function targetsCard(f) {
  const invInfo = h('div', { class: 'row' });
  const fileInput = h('input', {
    type: 'file', accept: '.csv,.txt,text/csv,text/plain', class: 'sr-only', tabindex: '-1',
    onchange: async e => {
      const file = e.target.files[0];
      e.target.value = '';
      if (!file) return;
      f.inventory = await file.text();
      f.inventoryName = file.name;
      paintInv();
    },
  });
  const paintInv = () => {
    clear(invInfo);
    if (f.inventory) {
      const n = f.inventory.split('\n').filter(l => l.trim() && !l.trim().startsWith('#') && !/^\s*(role|host)\s*,/i.test(l)).length;
      invInfo.append(h('span', { class: 'pill accent plain' }, svgIcon('file', 13), `${f.inventoryName || 'inventory'} · ${plural(n, 'device')}`),
        h('button', { class: 'btn btn-ghost', type: 'button', onclick: () => { f.inventory = ''; f.inventoryName = ''; paintInv(); } }, 'Remove'));
    } else {
      invInfo.append(h('button', { class: 'btn', type: 'button', onclick: () => fileInput.click() }, svgIcon('upload'), 'Import inventory CSV'),
        h('span', { class: 'hint' }, 'role,host,alias,version,community, or the Switch Port Mapper import format'));
    }
  };
  paintInv();
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, svgIcon('switch', 18), 'Targets'),
    h('div', { class: 'card-body stack' },
      field('Client / site', text(f, 'label', { placeholder: 'e.g. Contoso – Head office', maxlength: '120' }), 'Shown on the report and used in exported file names.'),
      field('Switches', area(f, 'switches', { rows: '5', placeholder: '10.0.0.2\n10.0.0.3:1161\ncore-sw.example.lan' }), 'One per line: host or host:port.'),
      field('ARP sources', area(f, 'arp', { rows: '3', placeholder: '10.0.0.1' }), 'Routers or L3 switches that know the IP addresses of the switches’ VLANs. Optional: switches are asked too.'),
      invInfo, fileInput));
}

function credsCard(f, meta) {
  const s = f.snmp;
  const body = h('div', { class: 'card-body stack' });
  const env = (meta && meta.env) || {};
  const seg = h('div', { class: 'segmented', role: 'group', 'aria-label': 'SNMP version' });
  const paint = () => {
    clear(seg);
    for (const [v, label] of [['1', 'v1'], ['2c', 'v2c'], ['3', 'v3']]) {
      seg.append(h('button', { type: 'button', 'aria-pressed': String(s.version === v), onclick: () => { s.version = v; paint(); } }, label));
    }
    clear(body).append(h('div', { class: 'row' }, h('span', { class: 'label' }, 'SNMP version'), seg));
    if (s.version === '3') {
      body.append(h('div', { class: 'fields' },
        field('User', text(s, 'v3_user', { autocomplete: 'off', placeholder: env.v3_user ? 'from PORTMAP_V3_USER' : '' })),
        field('Context', text(s, 'v3_context', { placeholder: 'optional' })),
        field('Auth protocol', select(s, 'v3_auth_proto', [['sha', 'SHA-1'], ['sha256', 'SHA-256'], ['sha384', 'SHA-384'], ['sha512', 'SHA-512'], ['sha224', 'SHA-224'], ['md5', 'MD5'], ['none', 'None']])),
        field('Auth passphrase', secret(s, 'v3_auth_pass', { placeholder: env.v3_auth_pass ? 'from PORTMAP_V3_AUTH_PASS' : '' })),
        field('Privacy protocol', select(s, 'v3_priv_proto', [['aes', 'AES-128'], ['aes256', 'AES-256'], ['aes192', 'AES-192'], ['aes256c', 'AES-256 (Cisco)'], ['aes192c', 'AES-192 (Cisco)'], ['des', 'DES'], ['none', 'None']])),
        field('Privacy passphrase', secret(s, 'v3_priv_pass', { placeholder: env.v3_priv_pass ? 'from PORTMAP_V3_PRIV_PASS' : '' }))));
    } else {
      body.append(field('Community', secret(s, 'community', { placeholder: env.community ? 'from PORTMAP_COMMUNITY' : 'public' }),
        env.community ? 'Leave empty to use PORTMAP_COMMUNITY from the environment that started atlas-portmap.' : 'Read-only community. Empty means "public".'));
    }
    body.append(h('div', { class: 'callout info' }, svgIcon('check', 16),
      h('span', null, 'Credentials are held in memory for this scan only: never written to disk, never sent back by the server. Read-only SNMP: nothing on the switches is changed.')));
  };
  paint();
  return h('section', { class: 'card' }, h('div', { class: 'card-head' }, svgIcon('eye', 18), 'Credentials'), body);
}

function optionsCard(f) {
  const o = f.options, s = f.snmp;
  return h('details', { class: 'card advanced' },
    h('summary', { class: 'card-head' }, svgIcon('chevron', 16), 'Advanced options', h('span', { class: 'sub' }, 'discovery, Cisco per-VLAN, SNMP tuning, extra columns')),
    h('div', { class: 'card-body stack' },
      h('div', { class: 'fields' },
        toggle(o, 'lldp', 'LLDP neighbours', 'Finds uplinks, phones and APs'),
        toggle(o, 'cdp', 'CDP neighbours', 'Cisco Discovery Protocol'),
        toggle(o, 'arp_from_switches', 'ARP from switches', 'L3 switches know their subnets'),
        toggle(o, 'local_arp', 'This computer’s ARP cache', 'Adds IPs this machine has seen'),
        toggle(o, 'resolve', 'Reverse DNS', 'Look up hostnames for IPs'),
        toggle(o, 'dot1x', '802.1X column', 'Port-control mode per port'),
        toggle(o, 'all_ports', 'All ports', 'Include free ports and uplinks'),
        toggle(o, 'all_sightings', 'All sightings', 'Every port that learned each MAC')),
      h('div', { class: 'fields' },
        field('Cisco per-VLAN', select(o, 'cisco_per_vlan', [['auto', 'Auto (Cisco without Q-BRIDGE)'], ['on', 'Always'], ['off', 'Never']])),
        field('VLANs for per-VLAN', text(o, 'vlans', { placeholder: 'from VTP, or e.g. 1,10-20' })),
        field('Uplink threshold', num(o, 'uplink_threshold', { min: '0' }), 'Ports with at least this many MACs count as uplinks (0 = off).'),
        field('MAC format', select(o, 'mac_format', [['colon', 'aa:bb:cc:dd:ee:ff'], ['dash', 'AA-BB-CC-DD-EE-FF'], ['dot', 'aabb.ccdd.eeff'], ['bare', 'aabbccddeeff']]))),
      h('div', { class: 'fields' },
        field('UDP port', num(s, 'port', { min: '1', max: '65535' })),
        field('Timeout (ms)', num(s, 'timeout_ms', { min: '100', step: '100' })),
        field('Retries', num(s, 'retries', { min: '0', max: '5' })),
        field('GETBULK size', num(s, 'max_reps', { min: '1', max: '500' }), 'Lower it for agents that drop large replies.'),
        field('Parallel devices', num(o, 'concurrency', { min: '1', max: '64' }))),
      field('Extra per-port columns', area(o, 'columns', { rows: '3', placeholder: 'duplex=1.3.6.1.2.1.10.7.2.1.19\nlastchange=1.3.6.1.2.1.2.2.1.9\nmtu=1.3.6.1.2.1.2.2.1.4' }),
        'One NAME=OID per line. The OID must be numeric and its table indexed by ifIndex (PoE’s pethPsePortTable is not).')));
}

// ---- progress ----

const ROLE_ICON = { switch: 'switch', arp: 'router', 'local-arp': 'laptop', dns: 'globe' };
const STATE_PILL = { queued: ['idle', 'Queued'], running: ['accent running', 'Running'], done: ['ok', 'Done'], failed: ['danger', 'Failed'], skipped: ['idle', 'Skipped'] };

// progress paints the scan card. While the same scan is running only the changing parts are
// updated in place, so the Cancel button and keyboard focus survive each 600 ms poll.
function progress(box) {
  const j = state.active;
  if (!j) {
    clear(box);
    delete box.dataset.job;
    return;
  }
  if (box.dataset.job === `${j.id}:${j.state}` && box._update) {
    box._update(j);
    return;
  }
  clear(box);
  box.dataset.job = `${j.id}:${j.state}`;
  const running = j.state === 'running';
  const pct = j.total ? Math.round((100 * j.done) / j.total) : 0;
  const bar = h('div');
  bar.style.width = `${pct}%`; // CSSOM: allowed under the page's CSP
  const head = h('div', { class: 'card-head' }, svgIcon('scan', 18),
    running ? 'Scanning…' : 'Last scan', h('span', { class: 'sub' }, j.label || ''),
    h('div', { class: 'end' },
      h('span', { class: `pill ${{ running: 'accent running', done: 'ok', failed: 'danger', cancelled: 'warn' }[j.state] || 'idle'}` }, j.state),
      h('span', { class: 'muted' }, `${j.done}/${j.total}`),
      running ? h('button', { class: 'btn btn-danger', type: 'button', onclick: () => cancelScan().catch(e => toast(e.message, 'error')) }, svgIcon('stop'), 'Cancel')
        : (j.state !== 'cancelled' && j.entries >= 0 ? h('a', { class: 'btn', href: '#/results' }, 'View results') : null)));
  const counter = head.querySelector('.end .muted');
  const list = h('div', { class: 'tasks' });
  const rows = [];
  const paintTask = (row, t) => {
    const [cls, label] = STATE_PILL[t.state] || ['idle', t.state];
    row.pill.className = `pill ${cls}`;
    row.pill.textContent = label;
    row.detail.className = t.error ? 't-detail err' : 't-detail';
    row.detail.textContent = t.error || t.detail || (t.role === 'arp' ? 'ARP table' : t.role === 'switch' ? 'forwarding table, interfaces, neighbours' : '');
    row.time.textContent = fmtMs(t.elapsed_ms);
  };
  for (const t of j.tasks || []) {
    const row = { pill: h('span'), detail: h('div'), time: h('div', { class: 't-time' }) };
    list.append(h('div', { class: 'task' },
      svgIcon(ROLE_ICON[t.role] || 'switch', 18),
      h('div', { class: 't-target', title: t.target }, t.alias ? `${t.alias} (${t.target})` : t.target),
      row.pill, row.detail, row.time));
    paintTask(row, t);
    rows.push(row);
  }
  const meter = h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct) }, bar);
  box.append(h('section', { class: 'card' }, head, h('div', { class: 'card-body stack' }, meter, list)));
  box._update = next => {
    const p = next.total ? Math.round((100 * next.done) / next.total) : 0;
    bar.style.width = `${p}%`;
    meter.setAttribute('aria-valuenow', String(p));
    if (counter) counter.textContent = `${next.done}/${next.total}`;
    (next.tasks || []).forEach((t, i) => rows[i] && paintTask(rows[i], t));
  };
}

export function render(main) {
  const f = form();
  const page = h('div', { class: 'page stack' });
  const box = h('div');
  const startBtn = h('button', { class: 'btn btn-primary btn-lg', type: 'button' }, svgIcon('play'), 'Start scan');
  const err = h('div');
  const syncBtn = () => { startBtn.disabled = !!(state.active && state.active.state === 'running'); };
  startBtn.addEventListener('click', async () => {
    clear(err);
    if (!f.switches.trim() && !f.inventory.trim()) {
      err.append(h('div', { class: 'callout danger' }, svgIcon('alert', 16), 'Add at least one switch, or import an inventory.'));
      return;
    }
    startBtn.disabled = true;
    try {
      const { inventoryName, ...payload } = f;
      await startScan(payload);
      window.scrollTo(0, 0);
    } catch (e) {
      err.append(h('div', { class: 'callout danger' }, svgIcon('alert', 16), e.message));
      syncBtn();
    }
  });
  page.append(
    pageHead('New scan', 'Find which device is on which switch port. Read-only SNMP v1, v2c or v3.'),
    box,
    h('div', { class: 'grid-2' }, targetsCard(f), credsCard(f, state.meta)),
    optionsCard(f),
    err,
    h('div', { class: 'row' }, startBtn,
      h('button', { class: 'btn btn-ghost', type: 'button', onclick: () => { state.form = structuredClone(DEFAULTS); window.dispatchEvent(new HashChangeEvent('hashchange')); } }, 'Reset form')));
  main.append(page);
  progress(box);
  box.hidden = !state.active;
  syncBtn();
  return subscribe((s, patch) => {
    if ('active' in patch) {
      progress(box);
      box.hidden = !state.active;
      syncBtn();
    }
  });
}
