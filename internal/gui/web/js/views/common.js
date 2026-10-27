// Pieces shared by several views.
import { h, svgIcon, emptyState, toast } from '../dom.js';

export function noReport() {
  return emptyState({
    icon: 'ports',
    title: 'No report selected',
    text: 'Run a scan against one or more switches, or open a report you saved earlier.',
    actions: [
      h('a', { class: 'btn btn-primary', href: '#/scan' }, svgIcon('play'), 'New scan'),
    ],
  });
}

export function statusPill(status) {
  const cls = { up: 'ok', down: 'idle', disabled: 'warn', dormant: 'idle', testing: 'warn' }[status] || 'idle';
  return status ? h('span', { class: `pill ${cls}` }, status) : '';
}

export function sub(text) {
  return text ? h('span', { class: 'sub' }, text) : null;
}

export function pageHead(title, subtitle, ...actions) {
  return h('div', { class: 'page-head' },
    h('div', null, h('h1', { class: 'page-title' }, title), subtitle ? h('p', { class: 'page-sub' }, subtitle) : null),
    h('div', { class: 'row' }, actions));
}

export function reportSubtitle(r) {
  const parts = [];
  if (r.label) parts.push(r.label);
  if (r.generated) parts.push(new Date(r.generated).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }));
  if (r.version) parts.push(`atlas-portmap ${r.version}`);
  return parts.join(' · ');
}

export async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`Copied ${text}`);
  } catch (_) {
    toast('Copy failed: the browser blocked clipboard access', 'error');
  }
}

/** 'switch' for a true uplink (faces another mapped switch), 'shared' for a port with a bridge or
 * many MACs behind it (still the right place for those devices), '' otherwise. */
export function uplinkKind(e) {
  if (!e.uplink) return '';
  if (e.uplink_kind) return e.uplink_kind === 'switch' ? 'switch' : 'shared';
  return /^faces /.test(e.uplink_reason || '') ? 'switch' : 'shared'; // reports from before uplink_kind
}

/** A switch's identity inside a report. Reports carry switch_index (its position in the switch
 * list); older ones fall back to address + name, since names and even addresses can repeat. */
export function switchKey(e) {
  return e.switch_index !== undefined && e.switch_index !== null ? `i${e.switch_index}` : `a${e.switch_addr}|${e.switch}`;
}

/** The key of the i-th switch summary, matching switchKey of its entries. */
export function summaryKey(r, s, i) {
  const indexed = (r.entries || []).some(e => e.switch_index !== undefined && e.switch_index !== null);
  return indexed ? `i${i}` : `a${s.target}|${s.name || s.target}`;
}

/** A port's identity inside a report: switch + ifIndex (or port label). */
export function portKey(e) {
  return `${switchKey(e)}\u0000${e.if_index > 0 ? 'i' + e.if_index : 'p' + e.port}`;
}

/** Splits a port label into [prefix, number] in linear time ("Gi1/0/24" -> ["Gi1/0/", "24"]).
 * A Junos logical unit suffix ("ge-0/0/5.0") is dropped first. */
export function splitPort(label) {
  let s = String(label || '').slice(0, 200);
  const unit = /\.\d{1,5}$/.exec(s);
  if (unit && unit.index > 0 && s.charCodeAt(unit.index - 1) >= 48 && s.charCodeAt(unit.index - 1) <= 57) s = s.slice(0, unit.index);
  let i = s.length;
  while (i > 0 && s.charCodeAt(i - 1) >= 48 && s.charCodeAt(i - 1) <= 57) i--;
  return i === s.length ? [s, s] : [s.slice(0, i), s.slice(i)];
}

/** Makes an element activate on Enter/Space as well as on click. */
export function keyActivate(el, fn) {
  el.tabIndex = 0;
  el.addEventListener('click', fn);
  el.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fn(e);
    }
  });
  return el;
}
