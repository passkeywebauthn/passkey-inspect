#!/usr/bin/env node
// passkey-inspect CLI entrypoint.

import { readFileSync, existsSync, statSync } from 'node:fs';
import { argv, stdin, stdout, stderr, exit } from 'node:process';
import {
  parse,
  detectAndParse,
  parseAuthData,
  parseAttestationObject,
  parseClientDataJSON,
  parseCredential,
  isCredentialJSON,
  autoDecode,
  b64uToBytes,
  b64ToBytes,
  hexToBytes,
} from '../src/index.js';
import { formatResult, jsonReplacer } from '../src/format.js';

const HELP = `passkey-inspect — decode WebAuthn / passkey payloads

USAGE
  passkey-inspect [OPTIONS] [INPUT]
  cat payload.bin | passkey-inspect [OPTIONS]

INPUT
  INPUT may be a file path or the encoded payload itself. If INPUT is
  omitted, stdin is read. clientDataJSON may be passed as raw JSON text.

OPTIONS
  --type=<kind>      Force a specific parser. One of:
                       auto (default), client, attestation, authdata
  --encoding=<enc>   Force input encoding. One of:
                       auto (default), b64u, b64, hex, bin
                     For stdin, 'bin' is implied unless overridden.
  --json             Emit a JSON document instead of pretty text.
  --no-color         Disable ANSI colors. (Auto-disabled when stdout is
                     not a TTY.)
  -h, --help         Show this help.
  -v, --version      Show version.

EXAMPLES
  # Decode an attestationObject pasted from devtools
  passkey-inspect 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViY...'

  # Decode authenticatorData from a hex blob
  passkey-inspect --encoding=hex 49960de5...

  # Pipe a clientDataJSON file
  cat clientDataJSON.bin | passkey-inspect --type=client

  # Get machine-readable output for a script
  passkey-inspect --json --no-color attestation.b64

  # Force authenticatorData parsing (for assertion responses)
  passkey-inspect --type=authdata 'SZYN5e...'

LEARN MORE
  https://www.passkeywebauthn.com
`;

function readPackageVersion() {
  try {
    const url = new URL('../package.json', import.meta.url);
    const pkg = JSON.parse(readFileSync(url, 'utf8'));
    return pkg.version;
  } catch {
    return '0.0.0';
  }
}

function parseArgs(args) {
  const opts = { type: 'auto', encoding: 'auto', json: false, color: undefined };
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-h' || a === '--help') return { help: true };
    if (a === '-v' || a === '--version') return { version: true };
    if (a === '--json') {
      opts.json = true;
      continue;
    }
    if (a === '--no-color') {
      opts.color = false;
      continue;
    }
    if (a === '--color') {
      opts.color = true;
      continue;
    }
    if (a.startsWith('--type=')) {
      opts.type = a.slice(7);
      continue;
    }
    if (a === '--type') {
      opts.type = args[++i];
      continue;
    }
    if (a.startsWith('--encoding=')) {
      opts.encoding = a.slice(11);
      continue;
    }
    if (a === '--encoding') {
      opts.encoding = args[++i];
      continue;
    }
    if (a === '--') {
      positional.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith('-')) {
      throw new Error(`unknown option: ${a}`);
    }
    positional.push(a);
  }
  opts.positional = positional;
  return opts;
}

function readStdinSync() {
  try {
    const buf = readFileSync(0);
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  } catch (e) {
    if (e.code === 'EAGAIN' || e.code === 'EWOULDBLOCK') return new Uint8Array(0);
    throw e;
  }
}

function loadInput(opts) {
  const arg = opts.positional[0];
  let bytes;
  let source;
  let encoding = opts.encoding;

  if (arg) {
    if (existsSync(arg) && statSync(arg).isFile()) {
      const buf = readFileSync(arg);
      bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
      source = `file:${arg}`;
      if (encoding === 'auto') {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim();
        if (text.startsWith('{')) {
          // JSON text file
        } else if (/^[A-Za-z0-9+/=_\-\s]+$/.test(text) && text.length < bytes.length + 4) {
          const d = autoDecode(text);
          bytes = d.bytes;
          encoding = d.encoding;
        } else {
          encoding = 'bin';
        }
      } else if (encoding === 'b64u') {
        bytes = b64uToBytes(new TextDecoder().decode(bytes).trim());
      } else if (encoding === 'b64') {
        bytes = b64ToBytes(new TextDecoder().decode(bytes).trim());
      } else if (encoding === 'hex') {
        bytes = hexToBytes(new TextDecoder().decode(bytes).trim());
      }
    } else {
      // Treat the argument as the encoded payload itself.
      source = 'argv';
      if (encoding === 'auto') {
        if (arg.trim().startsWith('{')) {
          bytes = new TextEncoder().encode(arg.trim());
          encoding = 'utf-8';
        } else {
          const d = autoDecode(arg);
          bytes = d.bytes;
          encoding = d.encoding;
        }
      } else if (encoding === 'b64u') {
        bytes = b64uToBytes(arg);
      } else if (encoding === 'b64') {
        bytes = b64ToBytes(arg);
      } else if (encoding === 'hex') {
        bytes = hexToBytes(arg);
      } else if (encoding === 'bin') {
        bytes = new TextEncoder().encode(arg);
      } else {
        throw new Error(`unknown encoding: ${encoding}`);
      }
    }
  } else {
    // stdin
    source = 'stdin';
    const raw = readStdinSync();
    if (raw.length === 0) {
      throw new Error('no input provided (pass a file path, a string, or pipe data via stdin)');
    }
    if (encoding === 'auto' || encoding === 'bin') {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(raw).trim();
      if (text.startsWith('{')) {
        bytes = new TextEncoder().encode(text);
        encoding = 'utf-8';
      } else if (/^[A-Za-z0-9+/=_\-\s]+$/.test(text) && text.length > 0) {
        const d = autoDecode(text);
        bytes = d.bytes;
        encoding = d.encoding;
      } else {
        bytes = raw;
        encoding = 'bin';
      }
    } else if (encoding === 'b64u') {
      bytes = b64uToBytes(new TextDecoder().decode(raw).trim());
    } else if (encoding === 'b64') {
      bytes = b64ToBytes(new TextDecoder().decode(raw).trim());
    } else if (encoding === 'hex') {
      bytes = hexToBytes(new TextDecoder().decode(raw).trim());
    } else {
      throw new Error(`unknown encoding: ${encoding}`);
    }
  }

  return { bytes, source, encoding };
}

function runParser(type, bytes, encoding) {
  if (type === 'auto') {
    // A full serialized credential (navigator.credentials response) pasted as JSON.
    if (bytes[0] === 0x7b) {
      try {
        const obj = JSON.parse(new TextDecoder().decode(bytes));
        if (isCredentialJSON(obj)) {
          return { type: 'credential', parsed: parseCredential(obj), inputEncoding: encoding, byteLength: bytes.length };
        }
      } catch {
        /* not a credential; fall through to blob detection */
      }
    }
    const r = detectAndParse(bytes);
    return { ...r, inputEncoding: encoding, byteLength: bytes.length };
  }
  if (type === 'client') {
    return { type: 'clientDataJSON', parsed: parseClientDataJSON(bytes), inputEncoding: encoding, byteLength: bytes.length };
  }
  if (type === 'attestation') {
    return { type: 'attestationObject', parsed: parseAttestationObject(bytes), inputEncoding: encoding, byteLength: bytes.length };
  }
  if (type === 'authdata') {
    return { type: 'authenticatorData', parsed: parseAuthData(bytes), inputEncoding: encoding, byteLength: bytes.length };
  }
  throw new Error(`unknown --type: ${type}`);
}

function main() {
  let opts;
  try {
    opts = parseArgs(argv.slice(2));
  } catch (e) {
    stderr.write(`error: ${e.message}\n\nrun \`passkey-inspect --help\` for usage.\n`);
    exit(2);
  }
  if (opts.help) {
    stdout.write(HELP);
    return;
  }
  if (opts.version) {
    stdout.write(readPackageVersion() + '\n');
    return;
  }

  let input;
  try {
    input = loadInput(opts);
  } catch (e) {
    stderr.write(`error: ${e.message}\n`);
    exit(1);
  }

  let result;
  try {
    result = runParser(opts.type, input.bytes, input.encoding);
  } catch (e) {
    stderr.write(`error: ${e.message}\n`);
    exit(1);
  }

  if (opts.json) {
    stdout.write(JSON.stringify(result, jsonReplacer, 2) + '\n');
    return;
  }

  const useColor = opts.color ?? (stdout.isTTY === true);
  stdout.write(formatResult(result, { color: useColor }));
}

main();
