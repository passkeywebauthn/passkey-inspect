// Parses WebAuthn `authenticatorData` per the WebAuthn Level 3 spec § 6.1.
//
//   rpIdHash      32 bytes (SHA-256 of the RP ID)
//   flags          1 byte  (UP | RFU1 | UV | BE | BS | RFU2 | AT | ED)
//   signCount      4 bytes (big-endian uint32)
//   [attestedCredentialData] — present iff AT flag set
//       aaguid              16 bytes
//       credentialIdLength   2 bytes (big-endian uint16)
//       credentialId         L bytes
//       credentialPublicKey  CBOR-encoded COSE_Key (variable length)
//   [extensions]            CBOR map, present iff ED flag set

import { decode } from './cbor.js';
import { parseCoseKey } from './cose.js';
import { bytesToHex, bytesToB64u } from './base64url.js';
import { formatAaguid } from './aaguid.js';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

export function parseFlags(flagsByte) {
  return {
    raw: flagsByte,
    hex: '0x' + flagsByte.toString(16).padStart(2, '0'),
    binary: flagsByte.toString(2).padStart(8, '0'),
    UP: Boolean(flagsByte & FLAG_UP),
    UV: Boolean(flagsByte & FLAG_UV),
    BE: Boolean(flagsByte & FLAG_BE),
    BS: Boolean(flagsByte & FLAG_BS),
    AT: Boolean(flagsByte & FLAG_AT),
    ED: Boolean(flagsByte & FLAG_ED),
    notes: {
      UP: 'User Presence — user interacted with the authenticator',
      UV: 'User Verified — user verification (PIN, biometric) succeeded',
      BE: 'Backup Eligible — credential MAY be backed up (passkey-capable)',
      BS: 'Backup State — credential IS currently backed up / synced',
      AT: 'Attested credential data included',
      ED: 'Extension data included',
    },
  };
}

export function parseAuthData(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseAuthData expects Uint8Array');
  if (bytes.length < 37) throw new RangeError(`authenticatorData too short: ${bytes.length} bytes (minimum 37)`);

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rpIdHash = bytes.subarray(0, 32);
  const flagsByte = bytes[32];
  const signCount = view.getUint32(33);

  const flags = parseFlags(flagsByte);

  const out = {
    length: bytes.length,
    rpIdHash: bytesToHex(rpIdHash),
    flags,
    signCount,
  };

  let offset = 37;

  if (flags.AT) {
    if (bytes.length < offset + 18) throw new RangeError('AT flag set but authData truncated before AAGUID');
    const aaguid = bytes.subarray(offset, offset + 16);
    offset += 16;
    const credIdLen = view.getUint16(offset);
    offset += 2;
    if (bytes.length < offset + credIdLen) throw new RangeError('credential ID length exceeds authData');
    const credentialId = bytes.subarray(offset, offset + credIdLen);
    offset += credIdLen;

    const rest = bytes.subarray(offset);
    let coseKey;
    let bytesRead;
    try {
      const r = decode(rest);
      coseKey = r.value;
      bytesRead = r.bytesRead;
    } catch (e) {
      throw new Error(`failed to decode credentialPublicKey CBOR: ${e.message}`);
    }
    offset += bytesRead;

    out.attestedCredentialData = {
      aaguid: formatAaguid(aaguid),
      credentialIdLength: credIdLen,
      credentialId: {
        hex: bytesToHex(credentialId),
        base64url: bytesToB64u(credentialId),
        length: credentialId.length,
      },
      credentialPublicKey: parseCoseKey(coseKey),
    };
  }

  if (flags.ED) {
    const rest = bytes.subarray(offset);
    if (rest.length === 0) {
      out.extensions = { warning: 'ED flag set but no extension data present' };
    } else {
      try {
        const r = decode(rest);
        out.extensions = r.value;
        offset += r.bytesRead;
      } catch (e) {
        out.extensions = { error: `failed to decode extensions CBOR: ${e.message}` };
      }
    }
  }

  if (offset < bytes.length) {
    out.trailingBytes = bytes.length - offset;
  }

  return out;
}
