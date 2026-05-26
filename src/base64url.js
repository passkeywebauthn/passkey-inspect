// Encoding helpers for WebAuthn payload input. Browsers serialize most
// WebAuthn binary fields with base64url; some servers re-encode as standard
// base64 or hex. We accept all three transparently.

export function b64uToBytes(input) {
  const s = String(input).trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = Buffer.from(padded, 'base64');
  return new Uint8Array(bin.buffer, bin.byteOffset, bin.byteLength);
}

export function b64ToBytes(input) {
  const bin = Buffer.from(String(input).trim().replace(/\s+/g, ''), 'base64');
  return new Uint8Array(bin.buffer, bin.byteOffset, bin.byteLength);
}

export function hexToBytes(input) {
  const s = String(input).trim().replace(/\s+/g, '').replace(/^0x/i, '');
  if (s.length % 2 !== 0) throw new Error('hex input has odd length');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

export function bytesToB64u(bytes) {
  return Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

// Auto-detect: try base64url first (the WebAuthn default), fall back to hex.
export function autoDecode(input) {
  const s = String(input).trim().replace(/\s+/g, '');
  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0 && s.length >= 8) {
    // Looks like hex. But could also be valid base64url; prefer hex when the
    // input contains no base64-only characters and is even-length.
    try {
      return { bytes: hexToBytes(s), encoding: 'hex' };
    } catch {
      /* fall through */
    }
  }
  if (/^[A-Za-z0-9+/=_-]+$/.test(s)) {
    return { bytes: b64uToBytes(s), encoding: 'base64url' };
  }
  throw new Error('input is not base64url, base64, or hex');
}
