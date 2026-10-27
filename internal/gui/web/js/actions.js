// Operations shared by views: loading scans, running a scan (with polling that survives
// navigation), opening and saving reports.
import { api, download } from './api.js';
import { state, update } from './store.js';
import { toast } from './dom.js';

export async function loadScans() {
  const scans = await api('GET', '/api/scans');
  update({ scans });
  return scans;
}

export async function selectScan(id) {
  if (!id) {
    update({ currentId: null, report: null });
    return;
  }
  const j = await api('GET', `/api/scans/${encodeURIComponent(id)}`);
  update({ currentId: id, report: j.report || null, filters: { ...state.filters, sw: '', vlan: '', port: '' } });
}

let timer = null;

export async function startScan(payload) {
  const j = await api('POST', '/api/scans', payload);
  update({ active: j });
  await loadScans();
  poll(j.id);
  return j;
}

export function resume(id) {
  poll(id);
}

function poll(id) {
  clearTimeout(timer);
  timer = setTimeout(async () => {
    let j;
    try {
      j = await api('GET', `/api/scans/${encodeURIComponent(id)}`);
    } catch (e) {
      toast(e.message, 'error');
      return;
    }
    update({ active: j });
    if (j.state === 'running') {
      poll(id);
      return;
    }
    await loadScans().catch(() => {});
    update({ currentId: j.id, report: j.report || null, filters: { ...state.filters, sw: '', vlan: '', port: '' } });
    if (j.state === 'done') {
      toast(`Scan finished: ${j.entries} endpoints on ${j.switches} switches`);
      if (location.hash.startsWith('#/scan')) location.hash = '#/results';
    } else if (j.state === 'failed') {
      toast(j.error || 'Scan failed', 'error');
    } else {
      toast('Scan cancelled');
    }
  }, 600);
}

export async function cancelScan() {
  if (state.active && state.active.state === 'running') {
    await api('POST', `/api/scans/${encodeURIComponent(state.active.id)}/cancel`);
  }
}

export async function openReportFile(file) {
  const text = await file.text();
  const j = await api('POST', `/api/reports?name=${encodeURIComponent(file.name)}`, text);
  await loadScans();
  update({ currentId: j.id, report: j.report || null, filters: { ...state.filters, sw: '', vlan: '', port: '' } });
  toast(`Opened ${file.name}`);
}

export async function removeScan(id) {
  await api('DELETE', `/api/scans/${encodeURIComponent(id)}`);
  const scans = await loadScans();
  if (state.currentId === id) await selectScan(scans.find(s => s.state !== 'running')?.id || null);
}

export function exportCurrent(format) {
  if (!state.currentId) return Promise.resolve();
  return download(`/api/scans/${encodeURIComponent(state.currentId)}/export?format=${format}`);
}

/** Endpoint rows: a MAC placed at its best location (one row per VLAN it was learned in). */
export function endpoints(report) {
  return (report?.entries || []).filter(e => e.mac && !e.secondary);
}

/** Devices: endpoint rows grouped per switch and MAC, so a router on a trunk counts once. */
export function devices(report) {
  const out = new Map();
  for (const e of endpoints(report)) {
    const k = `${e.switch_index}|${e.mac}`;
    if (!out.has(k)) out.set(k, []);
    out.get(k).push(e);
  }
  return [...out.values()];
}
