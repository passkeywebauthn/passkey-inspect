// CBOR decoder tests using vectors from RFC 8949 Appendix A.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decode } from '../src/cbor.js';
import { hexToBytes } from '../src/base64url.js';

function dec(hex) {
  return decode(hexToBytes(hex)).value;
}

test('unsigned integers', () => {
  assert.equal(dec('00'), 0);
  assert.equal(dec('01'), 1);
  assert.equal(dec('0a'), 10);
  assert.equal(dec('17'), 23);
  assert.equal(dec('1818'), 24);
  assert.equal(dec('1864'), 100);
  assert.equal(dec('1903e8'), 1000);
  assert.equal(dec('1a000f4240'), 1000000);
});

test('negative integers', () => {
  assert.equal(dec('20'), -1);
  assert.equal(dec('29'), -10);
  assert.equal(dec('3863'), -100);
});

test('byte strings', () => {
  const v = dec('40');
  assert.ok(v instanceof Uint8Array);
  assert.equal(v.length, 0);
  const v2 = dec('4401020304');
  assert.deepEqual(Array.from(v2), [1, 2, 3, 4]);
});

test('text strings', () => {
  assert.equal(dec('60'), '');
  assert.equal(dec('6161'), 'a');
  assert.equal(dec('6449455446'), 'IETF');
  assert.equal(dec('62225c'), '"\\');
});

test('arrays', () => {
  assert.deepEqual(dec('80'), []);
  assert.deepEqual(dec('83010203'), [1, 2, 3]);
  assert.deepEqual(dec('8301820203820405'), [1, [2, 3], [4, 5]]);
});

test('maps preserve order and are Map instances', () => {
  const m = dec('a26161016162820203');
  assert.ok(m instanceof Map);
  assert.equal(m.size, 2);
  assert.equal(m.get('a'), 1);
  assert.deepEqual(m.get('b'), [2, 3]);
  assert.deepEqual([...m.keys()], ['a', 'b']);
});

test('simple values', () => {
  assert.equal(dec('f4'), false);
  assert.equal(dec('f5'), true);
  assert.equal(dec('f6'), null);
  assert.equal(dec('f7'), undefined);
});

test('half-precision float', () => {
  assert.equal(dec('f90000'), 0);
  assert.equal(dec('f93c00'), 1);
  assert.equal(dec('f9c400'), -4);
});

test('indefinite-length array', () => {
  assert.deepEqual(dec('9f018202039f0405ffff'), [1, [2, 3], [4, 5]]);
});

test('indefinite-length map', () => {
  const m = dec('bf61610161629f0203ffff');
  assert.equal(m.get('a'), 1);
  assert.deepEqual(m.get('b'), [2, 3]);
});

test('tagged values are preserved as { tag, value }', () => {
  // tag 0 (date string) wrapping "2013-03-21T20:04:00Z"
  const v = dec('c074323031332d30332d32315432303a30343a30305a');
  assert.equal(v.tag, 0);
  assert.equal(v.value, '2013-03-21T20:04:00Z');
});
