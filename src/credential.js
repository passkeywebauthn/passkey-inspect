// Decode a whole serialized WebAuthn credential — the JSON object a browser
// hands back from navigator.credentials.create()/get() (as produced by
// PublicKeyCredential.toJSON() or libraries like @github/webauthn-json). Instead
// of pulling out one field at a time, paste the entire response and get every
// embedded structure decoded at once.

import { parseAttestationObject } from './attestation.js';
import { parseAuthData } from './authData.js';
import { parseClientDataJSON } from './clientData.js';
import { autoDecode, bytesToHex } from './base64url.js';

function decodeField(value) {
  // Response fields are base64url in JSON, but be forgiving about base64/hex too.
  const { bytes } = autoDecode(String(value));
  return bytes;
}

function bytesInfo(value) {
  const bytes = decodeField(value);
  return { base64url: String(value), hex: bytesToHex(bytes), length: bytes.length };
}

/** True if `obj` looks like a serialized PublicKeyCredential. */
export function isCredentialJSON(obj) {
  return !!(obj && typeof obj === 'object' && obj.response && typeof obj.response === 'object' &&
    (obj.response.clientDataJSON || obj.response.attestationObject || obj.response.authenticatorData));
}

/**
 * Parse a serialized credential (object or JSON string). Returns a structured
 * result with the ceremony type and a decoded `parts` array ready for display.
 */
export function parseCredential(input) {
  const obj = typeof input === 'string' ? JSON.parse(input) : input;
  if (!isCredentialJSON(obj)) {
    throw new Error('not a serialized WebAuthn credential (missing response.clientDataJSON/attestationObject/authenticatorData)');
  }
  const res = obj.response;
  const parts = [];

  if (res.clientDataJSON) {
    const bytes = decodeField(res.clientDataJSON);
    parts.push({ type: 'clientDataJSON', parsed: parseClientDataJSON(bytes), byteLength: bytes.length, inputEncoding: 'base64url' });
  }

  let ceremony;
  if (res.attestationObject) {
    const bytes = decodeField(res.attestationObject);
    parts.push({ type: 'attestationObject', parsed: parseAttestationObject(bytes), byteLength: bytes.length, inputEncoding: 'base64url' });
    ceremony = 'registration';
  } else if (res.authenticatorData) {
    const bytes = decodeField(res.authenticatorData);
    parts.push({ type: 'authenticatorData', parsed: parseAuthData(bytes), byteLength: bytes.length, inputEncoding: 'base64url' });
    ceremony = 'authentication';
  }

  const out = {
    ceremony: ceremony ?? 'unknown',
    id: obj.id ?? null,
    credentialType: obj.type ?? null,
    authenticatorAttachment: obj.authenticatorAttachment ?? null,
    parts,
  };
  if (res.signature) out.signature = bytesInfo(res.signature);
  if (res.userHandle) out.userHandle = bytesInfo(res.userHandle);
  return out;
}
