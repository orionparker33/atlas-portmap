// atlas-portmap web app: shell, view registry and router.
//
// Adding a screen: write views/<name>.js exporting render(container) (optionally returning a
// cleanup function) and register it below. The sidebar, routing and report selection come free.
import { h, svgIcon, clear, toast, fmtTime, isTyping } from './dom.js';
import { state, update, subscribe } from './store.js';
import { api, initToken } from './api.js';
import { loadScans, selectScan, openReportFile, exportCurrent, resume, endpoints } from './actions.js';
import * as scanView from './views/scan.js';
import * as resultsView from './views/results.js';
import * as switchesView from './views/switches.js';
import * as portsView from './views/ports.js';

const views = [];

/** registerView({id, title, icon, render(container) -> cleanup?, count?(state) -> number|null}) */
export function registerView(v) {
  views.push(v);
}

registerView({ id: 'scan', title: 'Scan', icon: 'scan', render: scanView.render });
registerView({ id: 'results', title: 'Results', icon: 'list', render: resultsView.render, count: s => (s.report ? endpoints(s.report).length : null) });
registerView({ id: 'switches', title: 'Switches', icon: 'switch', render: switchesView.render, count: s => (s.report ? (s.report.switches || []).length : null) });
registerView({ id: 'ports', title: 'Ports', icon: 'ports', render: portsView.render });

const ui = {};
let current = null;
let cleanup = null;

function shell() {
  const app = document.getElementById('app');
  clear(app);
  app.className = 'shell';
  ui.picker = h('select', { class: 'select', 'aria-label': 'Report', onchange: e => selectScan(e.target.value).catch(err => toast(err.message, 'error')) });
  const fileInput = h('input', {
    type: 'file', accept: '.json,application/json', class: 'sr-only', tabindex: '-1',
    onchange: e => {
      const f = e.target.files[0];
      e.target.value = '';
      if (f) openReportFile(f).catch(err => toast(err.message, 'error'));
    },
  });
  ui.save = h('button', { class: 'btn btn-ghost', title: 'Save this report as JSON', onclick: () => exportCurrent('json').catch(err => toast(err.message, 'error')) }, svgIcon('save'), 'Save');
  const topbar = h('header', { class: 'topbar' },
    h('div', { class: 'brand' }, h('img', { src: '/favicon.svg', alt: '' }), h('div', null, 'atlas-portmap', h('small', null, 'switch port mapper'))),
    h('div', { class: 'report-picker' }, h('span', { class: 'label muted' }, 'Report'), ui.picker),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn btn-ghost', title: 'Open a saved report (.json)', onclick: () => fileInput.click() }, svgIcon('open'), 'Open'),
    ui.save,
    themeButton(),
    h('button', { class: 'btn btn-ghost btn-icon', title: 'Stop atlas-portmap', 'aria-label': 'Stop atlas-portmap', onclick: quit }, svgIcon('power')),
    fileInput);
  ui.foot = h('div', { class: 'sidebar-foot' });
  ui.nav = h('nav', { class: 'sidebar', 'aria-label': 'Views' },
    views.map(v => h('a', { class: 'nav-item', href: `#/${v.id}`, dataset: { view: v.id } }, svgIcon(v.icon, 18), v.title, h('span', { class: 'nav-count' }))),
    ui.foot);
  ui.main = h('main', { class: 'main', id: 'main' });
  app.append(topbar, ui.nav, ui.main);
}

let pickerSig = '';

function chrome() {
  const sig = JSON.stringify([state.currentId, state.scans.map(s => [s.id, s.label, s.state, s.entries, s.finished])]);
  if (sig !== pickerSig) {
    pickerSig = sig;
    paintPicker();
  }
  ui.save.disabled = !state.report;
  for (const a of ui.nav.querySelectorAll('.nav-item')) {
    const v = views.find(x => x.id === a.dataset.view);
    const n = v && v.count ? v.count(state) : null;
    a.querySelector('.nav-count').textContent = n === null || n === undefined ? '' : String(n);
  }
  const ver = state.meta && state.meta.version; // a bare dotted version gets its 'v'; hashes and 'dev' stay as the CLI prints them
  clear(ui.foot).append(state.meta ? `${/^\d+\.\d+/.test(ver) ? 'v' + ver : ver} · ${state.meta.platform}` : '');
}

function paintPicker() {
  clear(ui.picker);
  if (!state.scans.length) {
    ui.picker.append(h('option', { value: '' }, 'No reports yet'));
    ui.picker.disabled = true;
  } else {
    ui.picker.disabled = false;
    for (const s of state.scans) {
      const name = s.label || (s.source === 'file' ? 'Saved report' : 'Scan');
      const st = s.state === 'done' ? `${s.entries} endpoints` : s.state;
      ui.picker.append(h('option', { value: s.id }, `${name} · ${fmtTime(s.finished || s.started)} · ${st}`));
    }
    ui.picker.value = state.currentId || '';
  }
}

function route() {
  const id = (/^#\/([\w-]+)/.exec(location.hash) || [])[1] || 'scan';
  const v = views.find(x => x.id === id) || views[0];
  for (const a of ui.nav.querySelectorAll('.nav-item')) {
    if (a.dataset.view === v.id) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  if (cleanup) cleanup();
  clear(ui.main);
  current = v;
  cleanup = v.render(ui.main) || null;
  ui.main.scrollTop = 0;
  document.title = `${v.title} · atlas-portmap`;
}

function themeButton() {
  const modes = ['auto', 'light', 'dark'];
  let mode = 'auto';
  try { mode = localStorage.getItem('atlas-portmap.theme') || 'auto'; } catch (_) { /* storage blocked */ }
  const btn = h('button', { class: 'btn btn-ghost btn-icon', 'aria-label': 'Change theme' });
  const apply = () => {
    if (mode === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', mode);
    clear(btn).append(svgIcon(mode === 'dark' ? 'moon' : mode === 'light' ? 'sun' : 'contrast'));
    btn.title = `Theme: ${mode} (click to change)`;
  };
  btn.addEventListener('click', () => {
    mode = modes[(modes.indexOf(mode) + 1) % modes.length];
    try { localStorage.setItem('atlas-portmap.theme', mode); } catch (_) { /* storage blocked */ }
    apply();
  });
  apply();
  return btn;
}

async function quit() {
  if (!confirm('Stop atlas-portmap? Scans that were not saved are lost.')) return;
  try { await api('POST', '/api/quit'); } catch (_) { /* already gone */ }
  document.body.append(h('div', { class: 'overlay' },
    h('div', { class: 'empty' }, h('h2', null, 'atlas-portmap has stopped'), h('p', null, 'You can close this tab. Start it again with "atlas-portmap gui".'))));
}

function noToken() {
  const app = document.getElementById('app');
  clear(app).append(h('div', { class: 'overlay' },
    h('div', { class: 'empty' },
      h('div', { class: 'icon' }, svgIcon('alert', 26)),
      h('h2', null, 'Open atlas-portmap from its link'),
      h('p', null, 'This page needs the session link that "atlas-portmap gui" prints when it starts (it ends in #token=…). Copy that link into the address bar.'))));
}

async function init() {
  if (!initToken()) {
    noToken();
    return;
  }
  shell();
  try {
    update({ meta: await api('GET', '/api/meta') });
  } catch (e) {
    if (e.status === 401) {
      noToken();
      return;
    }
    toast(e.message, 'error');
  }
  subscribe((s, patch) => {
    chrome();
    if ('report' in patch && current && current.id !== 'scan') route();
  });
  try {
    const scans = await loadScans();
    const running = scans.find(s => s.state === 'running');
    if (running) {
      update({ active: running });
      resume(running.id);
    }
    const shown = scans.find(s => s.state !== 'running' && s.entries > 0) || scans.find(s => s.state !== 'running');
    if (shown) await selectScan(shown.id);
  } catch (e) {
    toast(e.message, 'error');
  }
  chrome();
  window.addEventListener('hashchange', route);
  document.addEventListener('keydown', e => {
    if (e.key === '/' && !isTyping(e)) {
      const s = document.getElementById('search');
      if (s) {
        e.preventDefault();
        s.focus();
      }
    }
  });
  if (!location.hash || location.hash === '#' || location.hash === '#/') history.replaceState(null, '', location.pathname + (state.report ? '#/results' : '#/scan'));
  route();
}

init();
