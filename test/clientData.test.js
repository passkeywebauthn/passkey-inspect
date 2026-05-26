import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseClientDataJSON } from '../src/clientData.js';

const enc = (obj) => new TextEncoder().encode(JSON.stringify(obj));

test('parses webauthn.create', () => {
  const p = parseClientDataJSON(
    enc({
      type: 'webauthn.create',
      challenge: 'aGVsbG8td29ybGQ',
      origin: 'https://example.com',
      crossOrigin: false,
    }),
  );
  assert.equal(p.type, 'webauthn.create');
  assert.equal(p.origin, 'https://example.com');
  assert.equal(p.crossOrigin, false);
  assert.equal(p.warnings, undefined);
});

test('parses webauthn.get', () => {
  const p = parseClientDataJSON(
    enc({
      type: 'webauthn.get',
      challenge: 'Y2hhbGxlbmdl',
      origin: 'https://example.com',
    }),
  );
  assert.equal(p.type, 'webauthn.get');
});

test('warns on unexpected type', () => {
  const p = parseClientDataJSON(
    enc({
      type: 'payment.get',
      challenge: 'YQ',
      origin: 'https://example.com',
    }),
  );
  assert.ok(p.warnings.some((w) => /unexpected type/.test(w)));
});

test('warns on non-base64url challenge', () => {
  const p = parseClientDataJSON(
    enc({
      type: 'webauthn.create',
      challenge: 'has spaces!',
      origin: 'https://example.com',
    }),
  );
  assert.ok(p.warnings.some((w) => /base64url/.test(w)));
});

test('throws on invalid JSON', () => {
  assert.throws(() => parseClientDataJSON(new TextEncoder().encode('{not json')), /not valid JSON/);
});
