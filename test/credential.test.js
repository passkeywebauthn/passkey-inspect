import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse, parseCredential, isCredentialJSON } from '../src/index.js';
import { bytesToB64u, hexToBytes } from '../src/base64url.js';
import {
  cborMap, cborText, cborBytes, buildAuthData, buildES256Key, randomBytes,
} from './_helpers.js';

const enc = new TextEncoder();
const GOOGLE_AAGUID = hexToBytes('ea9b8d664d011d213ce4b6b48cb575d4');

function buildAttestationObjectB64u() {
  const authData = buildAuthData({
    rpIdHash: randomBytes(32),
    flags: 0x45, // UP | UV | AT
    signCount: 0,
    aaguid: GOOGLE_AAGUID,
    credentialId: randomBytes(16),
    coseKey: buildES256Key(randomBytes(32), randomBytes(32)),
  });
  const att = cborMap([
    [cborText('fmt'), cborText('none')],
    [cborText('attStmt'), cborMap([])],
    [cborText('authData'), cborBytes(authData)],
  ]);
  return bytesToB64u(att);
}

function clientDataB64u(type, origin) {
  return bytesToB64u(enc.encode(JSON.stringify({ type, challenge: 'Y2hhbGxlbmdl', origin })));
}

test('isCredentialJSON recognizes a registration response', () => {
  assert.equal(isCredentialJSON({ response: { clientDataJSON: 'x', attestationObject: 'y' } }), true);
  assert.equal(isCredentialJSON({ response: {} }), false);
  assert.equal(isCredentialJSON({ foo: 1 }), false);
});

test('parseCredential decodes a full registration response', () => {
  const cred = {
    id: 'AQIDBA',
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: clientDataB64u('webauthn.create', 'https://example.com'),
      attestationObject: buildAttestationObjectB64u(),
    },
  };
  const out = parseCredential(cred);
  assert.equal(out.ceremony, 'registration');
  assert.equal(out.parts.length, 2);

  const client = out.parts.find((p) => p.type === 'clientDataJSON');
  assert.equal(client.parsed.type, 'webauthn.create');
  assert.equal(client.parsed.origin, 'https://example.com');

  const att = out.parts.find((p) => p.type === 'attestationObject');
  assert.equal(att.parsed.fmt, 'none');
  assert.equal(att.parsed.authData.attestedCredentialData.aaguid.name, 'Google Password Manager');
});

test('parse() auto-detects a serialized credential from a JSON string', () => {
  const json = JSON.stringify({
    id: 'AQIDBA',
    type: 'public-key',
    response: {
      clientDataJSON: clientDataB64u('webauthn.get', 'https://example.com'),
      authenticatorData: bytesToB64u(buildAuthData({
        rpIdHash: randomBytes(32), flags: 0x05, signCount: 7,
      })),
      signature: bytesToB64u(randomBytes(64)),
      userHandle: bytesToB64u(enc.encode('user-123')),
    },
  });
  const result = parse(json);
  assert.equal(result.type, 'credential');
  assert.equal(result.parsed.ceremony, 'authentication');
  assert.equal(result.parsed.signature.length, 64);
  assert.ok(result.parsed.userHandle);
});

test('parseCredential rejects non-credential objects', () => {
  assert.throws(() => parseCredential({ hello: 'world' }), /not a serialized WebAuthn credential/);
});
