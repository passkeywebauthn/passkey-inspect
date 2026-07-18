// Public API. Decoder functions take Uint8Array input; the `parse` helper
// auto-detects which kind of WebAuthn payload it was given.

import { decode } from './cbor.js';
import { parseAuthData, parseFlags } from './authData.js';
import { parseAttestationObject } from './attestation.js';
import { parseClientDataJSON } from './clientData.js';
import { parseCoseKey } from './cose.js';
import { parseCredential, isCredentialJSON } from './credential.js';
import { lookupAaguid, AAGUID_NAMES } from './aaguid-names.js';
import { autoDecode, b64uToBytes, b64ToBytes, hexToBytes, bytesToHex, bytesToB64u } from './base64url.js';

export {
  parseAuthData,
  parseFlags,
  parseAttestationObject,
  parseClientDataJSON,
  parseCoseKey,
  parseCredential,
  isCredentialJSON,
  lookupAaguid,
  AAGUID_NAMES,
  autoDecode,
  b64uToBytes,
  b64ToBytes,
  hexToBytes,
  bytesToHex,
  bytesToB64u,
};

const TYPES = {
  CLIENT_DATA_JSON: 'clientDataJSON',
  ATTESTATION_OBJECT: 'attestationObject',
  AUTH_DATA: 'authenticatorData',
  CREDENTIAL: 'credential',
};

// Looks at the raw bytes and decides which WebAuthn structure they most
// plausibly represent. Returns { type, parsed } or throws.
export function detectAndParse(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('detectAndParse expects Uint8Array');
  if (bytes.length === 0) throw new Error('empty input');

  // clientDataJSON starts with '{' (0x7b) and is valid UTF-8 JSON.
  if (bytes[0] === 0x7b) {
    try {
      const parsed = parseClientDataJSON(bytes);
      if (parsed.type === 'webauthn.create' || parsed.type === 'webauthn.get') {
        return { type: TYPES.CLIENT_DATA_JSON, parsed };
      }
    } catch {
      /* fall through */
    }
  }

  // attestationObject: a CBOR map containing 'fmt' (text), 'attStmt' (map),
  // 'authData' (bytes). Major type 5 (map) starts with 0xa0..0xbf.
  if ((bytes[0] & 0xe0) === 0xa0) {
    try {
      const decoded = decode(bytes).value;
      if (decoded instanceof Map && decoded.has('fmt') && decoded.has('authData')) {
        return { type: TYPES.ATTESTATION_OBJECT, parsed: parseAttestationObject(bytes) };
      }
    } catch {
      /* fall through */
    }
  }

  // authenticatorData: opaque binary, ≥37 bytes, byte 33 is the flags byte.
  // We cannot positively identify it but it is the most common remaining case.
  if (bytes.length >= 37) {
    return { type: TYPES.AUTH_DATA, parsed: parseAuthData(bytes) };
  }

  throw new Error('could not recognize input as clientDataJSON, attestationObject, or authenticatorData');
}

// Convenience: accept a string in any common encoding, return detection result.
export function parse(input) {
  let bytes;
  let encoding;
  if (input instanceof Uint8Array) {
    bytes = input;
    encoding = 'bytes';
  } else if (input && typeof input === 'object') {
    // A pre-parsed serialized credential object.
    if (isCredentialJSON(input)) {
      return { type: TYPES.CREDENTIAL, parsed: parseCredential(input), inputEncoding: 'object', byteLength: 0 };
    }
    throw new TypeError('parse expects a string, Uint8Array, or serialized credential object');
  } else if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{')) {
      // Could be a bare clientDataJSON or a full serialized credential.
      try {
        const obj = JSON.parse(trimmed);
        if (isCredentialJSON(obj)) {
          return { type: TYPES.CREDENTIAL, parsed: parseCredential(obj), inputEncoding: 'json', byteLength: trimmed.length };
        }
      } catch {
        /* not JSON we recognize; fall through to byte handling */
      }
      bytes = new TextEncoder().encode(trimmed);
      encoding = 'utf-8';
    } else {
      const d = autoDecode(trimmed);
      bytes = d.bytes;
      encoding = d.encoding;
    }
  } else {
    throw new TypeError('parse expects Uint8Array or string');
  }
  const result = detectAndParse(bytes);
  return { ...result, inputEncoding: encoding, byteLength: bytes.length };
}

export { TYPES };
