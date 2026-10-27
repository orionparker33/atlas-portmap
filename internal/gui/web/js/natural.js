// Natural ordering (Gi1/0/2 before Gi1/0/10), matching the Go side.
const RUN = /(\d+)|(\D+)/g;

export function naturalCompare(a, b) {
  const ax = String(a ?? '').match(RUN) || [];
  const bx = String(b ?? '').match(RUN) || [];
  for (let i = 0; i < Math.min(ax.length, bx.length); i++) {
    const x = ax[i], y = bx[i];
    const xd = x.charCodeAt(0) >= 48 && x.charCodeAt(0) <= 57;
    const yd = y.charCodeAt(0) >= 48 && y.charCodeAt(0) <= 57;
    if (xd && yd) {
      const xn = x.replace(/^0+/, ''), yn = y.replace(/^0+/, '');
      if (xn.length !== yn.length) return xn.length - yn.length;
      if (xn !== yn) return xn < yn ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return ax.length - bx.length;
}
