// Tiny CBOR encoder + byte helpers used only by the test suite.
// We deliberately keep this here (not in src/) — the library decodes, it
// does not encode, and tests should not depend on production helpers to
// build their fixtures.

export function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function head(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, (n >> 8) & 0xff, n & 0xff);
  if (n < 0x100000000) {
    return Uint8Array.of(
      (major << 5) | 26,
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    );
  }
  throw new Error('value too large for test encoder');
}

export function cborUint(n) {
  return head(0, n);
}
export function cborNint(n) {
  // n is a positive JS number; the CBOR value is -1 - n
  return head(1, n);
}
export function cborBytes(b) {
  return concat(head(2, b.length), b);
}
export function cborText(s) {
  const b = new TextEncoder().encode(s);
  return concat(head(3, b.length), b);
}
export function cborArray(items) {
  return concat(head(4, items.length), ...items);
}
export function cborMap(entries) {
  // entries: [[keyBytes, valueBytes], ...]
  const parts = [head(5, entries.length)];
  for (const [k, v] of entries) {
    parts.push(k, v);
  }
  return concat(...parts);
}
export function cborInt(n) {
  return n >= 0 ? cborUint(n) : cborNint(-1 - n);
}

// Build a minimal ES256 (P-256) COSE_Key with the given x/y coordinates.
export function buildES256Key(x, y) {
  return cborMap([
    [cborInt(1), cborInt(2)],   // kty: EC2
    [cborInt(3), cborInt(-7)],  // alg: ES256
    [cborInt(-1), cborInt(1)],  // crv: P-256
    [cborInt(-2), cborBytes(x)], // x
    [cborInt(-3), cborBytes(y)], // y
  ]);
}

// Build authenticatorData with optional attested credential data.
export function buildAuthData({ rpIdHash, flags, signCount, aaguid, credentialId, coseKey }) {
  const view = new ArrayBuffer(4);
  new DataView(view).setUint32(0, signCount);
  const header = concat(rpIdHash, Uint8Array.of(flags), new Uint8Array(view));
  if ((flags & 0x40) === 0) return header;
  const lenBuf = new ArrayBuffer(2);
  new DataView(lenBuf).setUint16(0, credentialId.length);
  return concat(header, aaguid, new Uint8Array(lenBuf), credentialId, coseKey);
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = i + 1;
  return out;
}
