// COSE key parser (RFC 8152) limited to the algorithms WebAuthn relying
// parties actually see in practice.

import { bytesToHex } from './base64url.js';

const KTY = {
  1: 'OKP',
  2: 'EC2',
  3: 'RSA',
  4: 'Symmetric',
};

const ALG = {
  '-7': 'ES256 (ECDSA w/ SHA-256)',
  '-8': 'EdDSA',
  '-35': 'ES384 (ECDSA w/ SHA-384)',
  '-36': 'ES512 (ECDSA w/ SHA-512)',
  '-37': 'PS256 (RSASSA-PSS w/ SHA-256)',
  '-38': 'PS384 (RSASSA-PSS w/ SHA-384)',
  '-39': 'PS512 (RSASSA-PSS w/ SHA-512)',
  '-257': 'RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)',
  '-258': 'RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)',
  '-259': 'RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)',
  '-65535': 'RS1 (RSASSA-PKCS1-v1_5 w/ SHA-1) — deprecated',
};

const EC2_CRV = {
  1: 'P-256',
  2: 'P-384',
  3: 'P-521',
};

const OKP_CRV = {
  4: 'X25519',
  5: 'X448',
  6: 'Ed25519',
  7: 'Ed448',
};

function getKey(map, k) {
  if (!(map instanceof Map)) return undefined;
  if (map.has(k)) return map.get(k);
  if (typeof k === 'number' && map.has(BigInt(k))) return map.get(BigInt(k));
  return undefined;
}

export function parseCoseKey(map) {
  if (!(map instanceof Map)) {
    return { error: 'COSE key must be a CBOR map', raw: map };
  }
  const ktyRaw = getKey(map, 1);
  const algRaw = getKey(map, 3);
  const kty = KTY[Number(ktyRaw)] ?? `Unknown (${ktyRaw})`;
  const alg = ALG[String(algRaw)] ?? `Unknown (${algRaw})`;

  const out = {
    kty,
    ktyValue: Number(ktyRaw),
    alg,
    algValue: typeof algRaw === 'bigint' ? Number(algRaw) : algRaw,
  };

  if (Number(ktyRaw) === 2) {
    // EC2
    const crv = getKey(map, -1);
    const x = getKey(map, -2);
    const y = getKey(map, -3);
    out.crv = EC2_CRV[Number(crv)] ?? `Unknown (${crv})`;
    out.crvValue = Number(crv);
    if (x instanceof Uint8Array) out.x = bytesToHex(x);
    if (y instanceof Uint8Array) out.y = bytesToHex(y);
  } else if (Number(ktyRaw) === 1) {
    // OKP
    const crv = getKey(map, -1);
    const x = getKey(map, -2);
    out.crv = OKP_CRV[Number(crv)] ?? `Unknown (${crv})`;
    out.crvValue = Number(crv);
    if (x instanceof Uint8Array) out.x = bytesToHex(x);
  } else if (Number(ktyRaw) === 3) {
    // RSA
    const n = getKey(map, -1);
    const e = getKey(map, -2);
    if (n instanceof Uint8Array) {
      out.nBits = n.length * 8;
      out.n = bytesToHex(n);
    }
    if (e instanceof Uint8Array) out.e = bytesToHex(e);
  }

  return out;
}
