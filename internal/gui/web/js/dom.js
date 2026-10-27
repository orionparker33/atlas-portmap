// DOM helpers. Everything is built with createElement and textContent, never innerHTML, so text
// that comes from switches (port aliases, LLDP names, vendor strings) can never become markup.
import { ICONS } from './icons.js';

const PROPS = new Set(['value', 'checked', 'selected', 'disabled', 'indeterminate', 'open']);

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  let value;
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') value = v;
    else if (PROPS.has(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  if (value !== undefined) el.value = value; // after children, so <select> options exist
  return el;
}

export function append(el, children) {
  for (const c of [children].flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function svgIcon(name, size = 16) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor',
    'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(k, String(v));
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

export function toast(msg, kind) {
  let box = document.querySelector('.toasts');
  if (!box) {
    box = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(box);
  }
  const t = h('div', { class: kind === 'error' ? 'toast error' : 'toast' }, msg);
  box.append(t);
  setTimeout(() => t.remove(), kind === 'error' ? 8000 : 3500);
}

export function fmtTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function fmtMs(ms) {
  if (!ms) return '';
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)} s`;
}

export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : (many || one + 's')}`;
}

export function isTyping(e) {
  const t = e.target;
  return t && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName));
}

export function emptyState({ icon, title, text, actions }) {
  return h('div', { class: 'empty' },
    h('div', { class: 'icon' }, svgIcon(icon, 26)),
    h('h2', null, title),
    h('p', null, text),
    h('div', { class: 'row' }, actions || []));
}
