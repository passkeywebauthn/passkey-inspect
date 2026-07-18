// AAGUID utilities. AAGUIDs are 16-byte UUIDs identifying authenticator
// models. We format them as canonical UUID strings and call out the common
// "all zeros" case (which means the authenticator did not provide an
// AAGUID, typical for self-attestation or anonymized platform passkeys).

import { bytesToHex } from './base64url.js';
import { lookupAaguid } from './aaguid-names.js';

export function formatAaguid(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 16) {
    return { error: 'AAGUID must be 16 bytes', raw: bytes ? bytesToHex(bytes) : null };
  }
  const hex = bytesToHex(bytes);
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
  const isZero = bytes.every((b) => b === 0);
  return {
    uuid,
    isZero,
    // Human-readable model name when the AAGUID is a known authenticator.
    name: isZero ? undefined : lookupAaguid(uuid) ?? undefined,
    note: isZero
      ? 'all-zero AAGUID — authenticator did not identify its model (common for self-attestation, anonymized platform passkeys, or "none" attestation)'
      : undefined,
  };
}
