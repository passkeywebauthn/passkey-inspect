import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bytesToB64u } from '../src/base64url.js';
import { cborMap, cborText, cborBytes, buildAuthData, buildES256Key } from './_helpers.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, '..', 'bin', 'passkey-inspect.js');

function run(args, stdin) {
  return spawnSync(process.execPath, [CLI, ...args], {
    input: stdin,
    encoding: 'utf8',
  });
}

test('--help prints usage', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /passkey-inspect/);
  assert.match(r.stdout, /passkeywebauthn\.com/);
});

test('--version prints semver', () => {
  const r = run(['--version']);
  assert.equal(r.status, 0);
  assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('parses attestationObject from argv (base64url)', () => {
  const ad = buildAuthData({
    rpIdHash: new Uint8Array(32).fill(0x33),
    flags: 0x45,
    signCount: 7,
    aaguid: new Uint8Array(16),
    credentialId: new Uint8Array(16).fill(0xee),
    coseKey: buildES256Key(new Uint8Array(32).fill(9), new Uint8Array(32).fill(8)),
  });
  const obj = cborMap([
    [cborText('fmt'), cborText('none')],
    [cborText('attStmt'), cborMap([])],
    [cborText('authData'), cborBytes(ad)],
  ]);
  const b64u = bytesToB64u(obj);
  const r = run(['--no-color', '--json', b64u]);
  assert.equal(r.status, 0, r.stderr);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.type, 'attestationObject');
  assert.equal(parsed.parsed.fmt, 'none');
  assert.equal(parsed.parsed.authData.signCount, 7);
});

test('parses clientDataJSON from stdin', () => {
  const cdj = JSON.stringify({
    type: 'webauthn.create',
    challenge: 'YWJj',
    origin: 'https://example.com',
  });
  const r = run(['--no-color', '--json'], cdj);
  assert.equal(r.status, 0, r.stderr);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.type, 'clientDataJSON');
  assert.equal(parsed.parsed.origin, 'https://example.com');
});

test('exits non-zero on garbage input', () => {
  const r = run(['--no-color'], 'not-base64!@#$%');
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /error/);
});
