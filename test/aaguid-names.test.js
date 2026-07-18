import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatAaguid } from '../src/aaguid.js';
import { lookupAaguid } from '../src/aaguid-names.js';
import { hexToBytes } from '../src/base64url.js';

test('lookupAaguid resolves a known model and is case-insensitive', () => {
  assert.equal(lookupAaguid('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4'), 'Google Password Manager');
  assert.equal(lookupAaguid('EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4'), 'Google Password Manager');
  assert.equal(lookupAaguid('00000000-0000-0000-0000-000000000000'), null);
});

test('formatAaguid attaches a name for a known AAGUID', () => {
  const bytes = hexToBytes('ea9b8d664d011d213ce4b6b48cb575d4');
  const result = formatAaguid(bytes);
  assert.equal(result.uuid, 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4');
  assert.equal(result.name, 'Google Password Manager');
  assert.equal(result.isZero, false);
});

test('formatAaguid leaves name undefined for unknown/zero AAGUIDs', () => {
  const zero = formatAaguid(new Uint8Array(16));
  assert.equal(zero.isZero, true);
  assert.equal(zero.name, undefined);
  assert.ok(zero.note.includes('all-zero'));

  const unknown = formatAaguid(hexToBytes('11111111111111111111111111111111'));
  assert.equal(unknown.name, undefined);
});
