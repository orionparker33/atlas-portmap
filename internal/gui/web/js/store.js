// Application state. Kept in memory only: nothing here (including the scan form, which can hold
// SNMP credentials) is written to browser storage.
export const state = {
  meta: null,
  scans: [],        // job summaries, newest first
  currentId: null,  // job whose report is shown
  report: null,     // that job's report
  active: null,     // the scan being run or last run from this tab (full view, polled)
  filters: { q: '', sw: '', vlan: '', port: '', hideUplinks: false, showEmpty: false },
  sort: { key: 'switch', dir: 1 },
  form: null,
};

const subs = new Set();

export function subscribe(fn) {
  subs.add(fn);
  return () => subs.delete(fn);
}

export function update(patch) {
  Object.assign(state, patch);
  for (const fn of [...subs]) fn(state, patch);
}
