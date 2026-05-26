import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAttestationObject } from '../src/attestation.js';
import { cborMap, cborText, cborBytes, buildAuthData, buildES256Key } from './_helpers.js';

function buildNoneAttestation(authData) {
  return cborMap([
    [cborText('fmt'), cborText('none')],
    [cborText('attStmt'), cborMap([])],
    [cborText('authData'), cborBytes(authData)],
  ]);
}

test('parses fmt=none attestation', () => {
  const rpIdHash = new Uint8Array(32).fill(0x11);
  const ad = buildAuthData({
    rpIdHash,
    flags: 0x45,
    signCount: 0,
    aaguid: new Uint8Array(16),
    credentialId: new Uint8Array(16).fill(0xaa),
    coseKey: buildES256Key(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)),
  });
  const obj = buildNoneAttestation(ad);
  const p = parseAttestationObject(obj);
  assert.equal(p.fmt, 'none');
  assert.equal(p.fmtWarning, undefined);
  assert.deepEqual(p.attStmt, {});
  assert.equal(p.authData.flags.AT, true);
  assert.equal(p.authData.attestedCredentialData.credentialIdLength, 16);
});

test('flags warning on unknown fmt', () => {
  const ad = buildAuthData({
    rpIdHash: new Uint8Array(32),
    flags: 0x01,
    signCount: 0,
  });
  const obj = cborMap([
    [cborText('fmt'), cborText('weird-fmt')],
    [cborText('attStmt'), cborMap([])],
    [cborText('authData'), cborBytes(ad)],
  ]);
  const p = parseAttestationObject(obj);
  assert.match(p.fmtWarning, /unrecognized/);
});

test('warns when fmt=none has non-empty attStmt', () => {
  const ad = buildAuthData({
    rpIdHash: new Uint8Array(32),
    flags: 0x01,
    signCount: 0,
  });
  const obj = cborMap([
    [cborText('fmt'), cborText('none')],
    [cborText('attStmt'), cborMap([[cborText('x'), cborText('y')]])],
    [cborText('authData'), cborBytes(ad)],
  ]);
  const p = parseAttestationObject(obj);
  assert.match(p.attStmt.warning, /requires an empty map/);
});
