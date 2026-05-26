// Parses the WebAuthn attestation object (the `attestationObject` field of
// an `AuthenticatorAttestationResponse`). It is a CBOR map with three keys:
//
//   fmt:      string — attestation statement format identifier
//   attStmt:  map    — format-specific signature material
//   authData: bytes  — the authenticator data structure (see authData.js)

import { decode } from './cbor.js';
import { parseAuthData } from './authData.js';
import { bytesToHex } from './base64url.js';

const KNOWN_FORMATS = new Set([
  'none',
  'packed',
  'tpm',
  'android-key',
  'android-safetynet',
  'fido-u2f',
  'apple',
  'apple-appattest',
]);

function getEntry(map, key) {
  if (!(map instanceof Map)) return undefined;
  if (map.has(key)) return map.get(key);
  return undefined;
}

function summarizeAttStmt(fmt, stmt) {
  if (!(stmt instanceof Map)) return { warning: 'attStmt is not a CBOR map', raw: stmt };
  const summary = {};
  for (const [k, v] of stmt) {
    if (v instanceof Uint8Array) {
      summary[k] = { type: 'bytes', length: v.length, hex: bytesToHex(v) };
    } else if (Array.isArray(v) && v.every((x) => x instanceof Uint8Array)) {
      summary[k] = v.map((x) => ({ type: 'bytes', length: x.length, hex: bytesToHex(x) }));
    } else if (typeof v === 'bigint') {
      summary[k] = Number(v);
    } else {
      summary[k] = v;
    }
  }
  if (fmt === 'none' && stmt.size > 0) {
    summary.warning = 'fmt is "none" but attStmt is non-empty — spec requires an empty map';
  }
  return summary;
}

export function parseAttestationObject(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseAttestationObject expects Uint8Array');
  let decoded;
  try {
    decoded = decode(bytes).value;
  } catch (e) {
    throw new Error(`failed to decode attestationObject CBOR: ${e.message}`);
  }
  if (!(decoded instanceof Map)) {
    throw new Error('attestationObject must decode to a CBOR map');
  }
  const fmt = getEntry(decoded, 'fmt');
  const attStmt = getEntry(decoded, 'attStmt');
  const authDataBytes = getEntry(decoded, 'authData');

  const out = { fmt };
  if (!KNOWN_FORMATS.has(fmt)) {
    out.fmtWarning = `unrecognized attestation format "${fmt}" — not one of the registered WebAuthn formats`;
  }
  out.attStmt = summarizeAttStmt(fmt, attStmt);

  if (authDataBytes instanceof Uint8Array) {
    try {
      out.authData = parseAuthData(authDataBytes);
    } catch (e) {
      out.authData = { error: e.message, length: authDataBytes.length, hex: bytesToHex(authDataBytes) };
    }
  } else {
    out.authData = { error: 'authData missing or not a byte string', raw: authDataBytes };
  }

  return out;
}
