import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuthData, parseFlags } from '../src/authData.js';
import { buildAuthData, buildES256Key, randomBytes } from './_helpers.js';

test('assertion authData (UP|UV, no AT, no ED)', () => {
  const rpIdHash = randomBytes(32);
  const ad = buildAuthData({ rpIdHash, flags: 0x05, signCount: 42 });
  const p = parseAuthData(ad);
  assert.equal(p.length, 37);
  assert.equal(p.signCount, 42);
  assert.equal(p.flags.UP, true);
  assert.equal(p.flags.UV, true);
  assert.equal(p.flags.AT, false);
  assert.equal(p.flags.BE, false);
  assert.equal(p.flags.BS, false);
  assert.equal(p.attestedCredentialData, undefined);
});

test('registration authData with attested credential data (ES256)', () => {
  const rpIdHash = new Uint8Array(32).fill(0xab);
  const aaguid = new Uint8Array(16).fill(0);
  const credentialId = new Uint8Array(20).fill(0xcd);
  const x = new Uint8Array(32).fill(0x11);
  const y = new Uint8Array(32).fill(0x22);
  const coseKey = buildES256Key(x, y);
  const ad = buildAuthData({
    rpIdHash,
    flags: 0x45, // UP | AT
    signCount: 0,
    aaguid,
    credentialId,
    coseKey,
  });
  const p = parseAuthData(ad);
  assert.equal(p.flags.UP, true);
  assert.equal(p.flags.AT, true);
  assert.equal(p.signCount, 0);
  assert.equal(p.attestedCredentialData.credentialIdLength, 20);
  assert.equal(p.attestedCredentialData.aaguid.uuid, '00000000-0000-0000-0000-000000000000');
  assert.equal(p.attestedCredentialData.aaguid.isZero, true);
  const k = p.attestedCredentialData.credentialPublicKey;
  assert.equal(k.kty, 'EC2');
  assert.equal(k.algValue, -7);
  assert.equal(k.crv, 'P-256');
  assert.equal(k.x.length, 64); // 32 bytes -> 64 hex chars
  assert.equal(k.y.length, 64);
});

test('passkey backup flags (BE|BS) round-trip', () => {
  const rpIdHash = randomBytes(32);
  const ad = buildAuthData({ rpIdHash, flags: 0x1d, signCount: 1 }); // UP|UV|BE|BS
  const p = parseAuthData(ad);
  assert.equal(p.flags.UP, true);
  assert.equal(p.flags.UV, true);
  assert.equal(p.flags.BE, true);
  assert.equal(p.flags.BS, true);
});

test('truncated authData throws', () => {
  assert.throws(() => parseAuthData(new Uint8Array(20)), /too short/);
});

test('AT flag with truncated body throws', () => {
  const head = new Uint8Array(37);
  head[32] = 0x40; // AT flag set but no body
  assert.throws(() => parseAuthData(head), /truncated|AAGUID/);
});

test('parseFlags exposes raw, hex, binary', () => {
  const f = parseFlags(0x45);
  assert.equal(f.raw, 0x45);
  assert.equal(f.hex, '0x45');
  assert.equal(f.binary, '01000101');
  assert.equal(f.UP, true);
  assert.equal(f.AT, true);
});
