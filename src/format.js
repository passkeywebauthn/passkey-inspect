// Pretty-printer for parsed WebAuthn payloads. Output is plain text with
// optional ANSI color. We avoid `console.log({...})` so the formatting can
// be tuned to highlight the fields developers care about (flags, AAGUID,
// COSE algorithm) without dumping raw byte arrays.

import { bytesToHex } from './base64url.js';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  red: '\x1b[31m',
  gray: '\x1b[90m',
};

function paint(color, useColor) {
  return useColor ? color : '';
}

function header(title, color, useColor) {
  const c = paint(ANSI[color] ?? ANSI.cyan, useColor);
  const r = paint(ANSI.reset, useColor);
  const b = paint(ANSI.bold, useColor);
  return `${b}${c}━━ ${title} ━━${r}\n`;
}

function kv(key, value, useColor, indent = '  ') {
  const k = paint(ANSI.dim, useColor) + key + paint(ANSI.reset, useColor);
  return `${indent}${k}: ${value}\n`;
}

function bool(v, useColor) {
  if (v === true) return paint(ANSI.green, useColor) + 'true' + paint(ANSI.reset, useColor);
  if (v === false) return paint(ANSI.gray, useColor) + 'false' + paint(ANSI.reset, useColor);
  return String(v);
}

function truncateHex(hex, max = 64) {
  if (hex.length <= max) return hex;
  return hex.slice(0, max) + paint('', false) + '… (' + (hex.length / 2) + ' bytes total)';
}

function formatFlags(flags, useColor) {
  let out = '';
  out += kv('raw', `${flags.hex} (${flags.binary}b)`, useColor);
  const order = ['UP', 'UV', 'BE', 'BS', 'AT', 'ED'];
  for (const f of order) {
    const note = flags.notes[f];
    out += kv(f, `${bool(flags[f], useColor)} ${paint(ANSI.gray, useColor)}— ${note}${paint(ANSI.reset, useColor)}`, useColor);
  }
  return out;
}

function formatCoseKey(k, useColor) {
  let out = '';
  out += kv('kty', `${k.kty} (${k.ktyValue})`, useColor);
  out += kv('alg', `${k.alg}`, useColor);
  if (k.crv) out += kv('crv', `${k.crv} (${k.crvValue})`, useColor);
  if (k.x) out += kv('x', truncateHex(k.x), useColor);
  if (k.y) out += kv('y', truncateHex(k.y), useColor);
  if (k.n) out += kv('n', `${k.nBits}-bit modulus: ${truncateHex(k.n)}`, useColor);
  if (k.e) out += kv('e', k.e, useColor);
  if (k.error) out += kv('error', paint(ANSI.red, useColor) + k.error + paint(ANSI.reset, useColor), useColor);
  return out;
}

function formatAuthData(a, useColor, indent = '  ') {
  let out = '';
  out += kv('length', `${a.length} bytes`, useColor, indent);
  out += kv('rpIdHash', truncateHex(a.rpIdHash), useColor, indent);
  out += kv('signCount', String(a.signCount), useColor, indent);
  out += indent + paint(ANSI.dim, useColor) + 'flags:' + paint(ANSI.reset, useColor) + '\n';
  out += formatFlags(a.flags, useColor).replace(/^ {2}/gm, indent + '  ');
  if (a.attestedCredentialData) {
    const acd = a.attestedCredentialData;
    out += indent + paint(ANSI.dim, useColor) + 'attestedCredentialData:' + paint(ANSI.reset, useColor) + '\n';
    const inner = indent + '  ';
    out += kv('aaguid', acd.aaguid.uuid, useColor, inner);
    if (acd.aaguid.note) {
      out += inner + '  ' + paint(ANSI.gray, useColor) + acd.aaguid.note + paint(ANSI.reset, useColor) + '\n';
    }
    out += kv('credentialId.length', String(acd.credentialIdLength), useColor, inner);
    out += kv('credentialId.b64u', acd.credentialId.base64url, useColor, inner);
    out += kv('credentialId.hex', truncateHex(acd.credentialId.hex), useColor, inner);
    out += inner + paint(ANSI.dim, useColor) + 'credentialPublicKey:' + paint(ANSI.reset, useColor) + '\n';
    out += formatCoseKey(acd.credentialPublicKey, useColor).replace(/^ {2}/gm, inner + '  ');
  }
  if (a.extensions !== undefined) {
    out += kv('extensions', JSON.stringify(a.extensions, jsonReplacer), useColor, indent);
  }
  if (a.trailingBytes) {
    out += kv('trailingBytes', paint(ANSI.yellow, useColor) + `${a.trailingBytes} (unexpected — possible parsing issue upstream)` + paint(ANSI.reset, useColor), useColor, indent);
  }
  return out;
}

export function jsonReplacer(_key, value) {
  if (value instanceof Uint8Array) return { __bytes__: bytesToHex(value), length: value.length };
  if (value instanceof Map) {
    const obj = {};
    for (const [k, v] of value) obj[String(k)] = v;
    return obj;
  }
  if (typeof value === 'bigint') return value.toString() + 'n';
  return value;
}

export function formatResult(result, opts = {}) {
  const useColor = opts.color !== false;
  const lines = [];
  lines.push(header(`passkey-inspect — ${result.type}`, 'cyan', useColor));
  lines.push(kv('inputEncoding', result.inputEncoding, useColor));
  lines.push(kv('byteLength', String(result.byteLength), useColor));
  lines.push('\n');

  if (result.type === 'clientDataJSON') {
    const p = result.parsed;
    lines.push(kv('type', p.type, useColor));
    lines.push(kv('challenge', p.challenge, useColor));
    lines.push(kv('origin', p.origin, useColor));
    lines.push(kv('crossOrigin', bool(p.crossOrigin, useColor), useColor));
    if (p.topOrigin) lines.push(kv('topOrigin', p.topOrigin, useColor));
    if (p.tokenBinding) lines.push(kv('tokenBinding', JSON.stringify(p.tokenBinding), useColor));
    if (p.warnings) {
      for (const w of p.warnings) {
        lines.push('  ' + paint(ANSI.yellow, useColor) + '⚠ ' + w + paint(ANSI.reset, useColor) + '\n');
      }
    }
  } else if (result.type === 'attestationObject') {
    const p = result.parsed;
    lines.push(kv('fmt', p.fmt, useColor));
    if (p.fmtWarning) {
      lines.push('  ' + paint(ANSI.yellow, useColor) + '⚠ ' + p.fmtWarning + paint(ANSI.reset, useColor) + '\n');
    }
    lines.push('  ' + paint(ANSI.dim, useColor) + 'attStmt:' + paint(ANSI.reset, useColor) + '\n');
    for (const [k, v] of Object.entries(p.attStmt)) {
      if (v && typeof v === 'object' && v.type === 'bytes') {
        lines.push(kv(k, `bytes(${v.length}) ${truncateHex(v.hex)}`, useColor, '    '));
      } else if (Array.isArray(v)) {
        lines.push('    ' + paint(ANSI.dim, useColor) + k + ':' + paint(ANSI.reset, useColor) + '\n');
        v.forEach((item, i) => {
          if (item && item.type === 'bytes') {
            lines.push(kv(`[${i}]`, `bytes(${item.length}) ${truncateHex(item.hex)}`, useColor, '      '));
          } else {
            lines.push(kv(`[${i}]`, JSON.stringify(item, jsonReplacer), useColor, '      '));
          }
        });
      } else {
        lines.push(kv(k, typeof v === 'string' ? v : JSON.stringify(v, jsonReplacer), useColor, '    '));
      }
    }
    lines.push('  ' + paint(ANSI.dim, useColor) + 'authData:' + paint(ANSI.reset, useColor) + '\n');
    if (p.authData.error) {
      lines.push('    ' + paint(ANSI.red, useColor) + 'error: ' + p.authData.error + paint(ANSI.reset, useColor) + '\n');
    } else {
      lines.push(formatAuthData(p.authData, useColor, '    '));
    }
  } else if (result.type === 'authenticatorData') {
    lines.push(formatAuthData(result.parsed, useColor));
  } else {
    lines.push(JSON.stringify(result.parsed, jsonReplacer, 2) + '\n');
  }

  return lines.join('');
}
