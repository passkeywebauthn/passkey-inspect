// Minimal CBOR decoder covering the subset used by WebAuthn / CTAP2.
// Implements RFC 8949 major types 0-7 with both definite and indefinite
// length encodings. Returns plain JS values; CBOR maps become Map objects
// to preserve non-string keys and ordering.

const MT_UINT = 0;
const MT_NINT = 1;
const MT_BYTES = 2;
const MT_TEXT = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;
const MT_SIMPLE = 7;

const BREAK = Symbol('cbor-break');

class Decoder {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  remaining() {
    return this.buf.length - this.pos;
  }

  readU8() {
    if (this.pos >= this.buf.length) throw new RangeError('CBOR: unexpected end of input');
    return this.buf[this.pos++];
  }

  readBytes(n) {
    if (this.pos + n > this.buf.length) throw new RangeError('CBOR: unexpected end of input');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  readArgument(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return this.readU8();
    if (ai === 25) {
      const v = this.view.getUint16(this.pos);
      this.pos += 2;
      return v;
    }
    if (ai === 26) {
      const v = this.view.getUint32(this.pos);
      this.pos += 4;
      return v;
    }
    if (ai === 27) {
      const hi = this.view.getUint32(this.pos);
      const lo = this.view.getUint32(this.pos + 4);
      this.pos += 8;
      const big = (BigInt(hi) << 32n) | BigInt(lo);
      return big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big;
    }
    if (ai === 31) return null; // indefinite-length sentinel
    throw new RangeError(`CBOR: reserved additional info ${ai}`);
  }

  decodeFloat16(u16) {
    const sign = (u16 & 0x8000) >> 15;
    const exp = (u16 & 0x7c00) >> 10;
    const frac = u16 & 0x03ff;
    let value;
    if (exp === 0) {
      value = Math.pow(2, -14) * (frac / 1024);
    } else if (exp === 0x1f) {
      value = frac ? NaN : Infinity;
    } else {
      value = Math.pow(2, exp - 15) * (1 + frac / 1024);
    }
    return sign ? -value : value;
  }

  next() {
    const first = this.readU8();
    const mt = first >> 5;
    const ai = first & 0x1f;

    if (mt === MT_SIMPLE) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 24) return { simple: this.readU8() };
      if (ai === 25) {
        const v = this.view.getUint16(this.pos);
        this.pos += 2;
        return this.decodeFloat16(v);
      }
      if (ai === 26) {
        const v = this.view.getFloat32(this.pos);
        this.pos += 4;
        return v;
      }
      if (ai === 27) {
        const v = this.view.getFloat64(this.pos);
        this.pos += 8;
        return v;
      }
      if (ai === 31) return BREAK;
      return { simple: ai };
    }

    if (ai === 31) {
      // Indefinite length
      if (mt === MT_BYTES) {
        const parts = [];
        let total = 0;
        for (;;) {
          const v = this.next();
          if (v === BREAK) break;
          if (!(v instanceof Uint8Array)) throw new TypeError('CBOR: indefinite bytes chunk must be byte string');
          parts.push(v);
          total += v.length;
        }
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) {
          out.set(p, off);
          off += p.length;
        }
        return out;
      }
      if (mt === MT_TEXT) {
        let s = '';
        for (;;) {
          const v = this.next();
          if (v === BREAK) break;
          if (typeof v !== 'string') throw new TypeError('CBOR: indefinite text chunk must be text string');
          s += v;
        }
        return s;
      }
      if (mt === MT_ARRAY) {
        const arr = [];
        for (;;) {
          const v = this.next();
          if (v === BREAK) break;
          arr.push(v);
        }
        return arr;
      }
      if (mt === MT_MAP) {
        const m = new Map();
        for (;;) {
          const k = this.next();
          if (k === BREAK) break;
          const v = this.next();
          m.set(k, v);
        }
        return m;
      }
      throw new RangeError(`CBOR: indefinite length not valid for major type ${mt}`);
    }

    const arg = this.readArgument(ai);

    switch (mt) {
      case MT_UINT:
        return arg;
      case MT_NINT:
        if (typeof arg === 'bigint') return -1n - arg;
        return -1 - arg;
      case MT_BYTES:
        return this.readBytes(Number(arg)).slice();
      case MT_TEXT: {
        const b = this.readBytes(Number(arg));
        return new TextDecoder('utf-8', { fatal: false }).decode(b);
      }
      case MT_ARRAY: {
        const n = Number(arg);
        const arr = new Array(n);
        for (let i = 0; i < n; i++) arr[i] = this.next();
        return arr;
      }
      case MT_MAP: {
        const n = Number(arg);
        const m = new Map();
        for (let i = 0; i < n; i++) {
          const k = this.next();
          const v = this.next();
          m.set(k, v);
        }
        return m;
      }
      case MT_TAG: {
        // Preserve tag wrapper so callers can introspect, but most WebAuthn
        // payloads do not use tags meaningfully.
        const inner = this.next();
        return { tag: Number(arg), value: inner };
      }
    }
    throw new RangeError(`CBOR: unhandled major type ${mt}`);
  }
}

export function decode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('decode expects Uint8Array');
  const d = new Decoder(bytes);
  const value = d.next();
  return { value, bytesRead: d.pos };
}

export function decodeAll(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('decodeAll expects Uint8Array');
  const d = new Decoder(bytes);
  const out = [];
  while (d.remaining() > 0) out.push(d.next());
  return out;
}

export function decodeFirst(bytes) {
  return decode(bytes).value;
}
