// API client. The session token arrives once in the URL fragment (#token=…), is kept in
// sessionStorage for this tab, and travels only in the X-Portmap-Token header.
const KEY = 'atlas-portmap.token';
let token = '';

export function initToken() {
  const m = /(?:^#|&)token=([0-9a-f]{64})/.exec(location.hash);
  if (m) {
    token = m[1];
    try { sessionStorage.setItem(KEY, token); } catch (_) { /* storage blocked: keep it in memory */ }
    const view = /(?:^#|&)view=([\w-]+)/.exec(location.hash); // optional deep link: #token=…&view=results
    history.replaceState(null, '', location.pathname + '#/' + (view ? view[1] : ''));
  } else {
    try { token = sessionStorage.getItem(KEY) || ''; } catch (_) { token = ''; }
  }
  return token !== '';
}

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export async function api(method, path, body) {
  const headers = { 'X-Portmap-Token': token };
  const init = { method, headers, cache: 'no-store' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (_) {
    throw new ApiError(0, 'atlas-portmap is not running (the GUI server has stopped)');
  }
  if (res.status === 204) return null;
  const isJSON = (res.headers.get('Content-Type') || '').includes('application/json');
  const data = isJSON ? await res.json() : await res.text();
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || String(data) || res.statusText);
  return data;
}

export async function download(path) {
  const res = await fetch(path, { headers: { 'X-Portmap-Token': token }, cache: 'no-store' });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (_) { /* not JSON */ }
    throw new ApiError(res.status, msg);
  }
  const blob = await res.blob();
  const m = /filename="([^"]+)"/.exec(res.headers.get('Content-Disposition') || '');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : 'portmap-export';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}
