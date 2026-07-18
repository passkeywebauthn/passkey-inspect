# passkey-inspect

> Zero-dependency CLI and library to decode and pretty-print WebAuthn / passkey payloads.

`passkey-inspect` decodes the binary blobs that the [WebAuthn API](https://www.w3.org/TR/webauthn-3/) hands developers — `attestationObject`, `authenticatorData`, `clientDataJSON`, COSE public keys — and prints them in a form you can actually read while debugging.

It runs entirely offline, has **no runtime dependencies**, and works on Node.js ≥ 18.

Built and maintained by the team behind **[passkeywebauthn.com — the Passkey & WebAuthn Engineering Hub](https://www.passkeywebauthn.com)**.

---

## Why

Every WebAuthn-shaped bug eventually comes down to staring at a base64url blob and asking "what's actually in there?" The answer involves CBOR, COSE, AAGUIDs, eight flag bits packed into one byte, and at least three nested byte strings. `passkey-inspect` turns that staring contest into one command:

```
$ passkey-inspect 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViY...'

━━ passkey-inspect — attestationObject ━━
  inputEncoding: base64url
  byteLength: 196

  fmt: none
  attStmt: {}
  authData:
    length: 148 bytes
    rpIdHash: 49960de5880e8c687434170f6476605b8fe4aeb9...
    signCount: 0
    flags:
      raw: 0x5d (01011101b)
      UP: true  — User Presence
      UV: true  — User Verified
      BE: true  — Backup Eligible (passkey-capable)
      BS: true  — Backup State (synced)
      AT: true  — Attested credential data included
      ED: false
    attestedCredentialData:
      aaguid: 00000000-0000-0000-0000-000000000000
        all-zero AAGUID — authenticator did not identify its model
      credentialId.length: 16
      credentialId.b64u: <id>
      credentialPublicKey:
        kty: EC2 (2)
        alg: ES256 (ECDSA w/ SHA-256)
        crv: P-256 (1)
        x: <32-byte hex>
        y: <32-byte hex>
```

## Install

```sh
npm install -g passkey-inspect
# or run without installing
npx passkey-inspect --help
```

## CLI usage

```
passkey-inspect [OPTIONS] [INPUT]
cat payload.bin | passkey-inspect [OPTIONS]
```

`INPUT` may be a file path, an encoded string, or piped via stdin. Encoding is auto-detected (base64url, base64, hex, raw JSON, binary).

| Flag | Purpose |
|------|---------|
| `--type=<auto\|client\|attestation\|authdata>` | Force a specific parser. Default: auto-detect. |
| `--encoding=<auto\|b64u\|b64\|hex\|bin>` | Force input encoding. |
| `--json` | Emit JSON instead of pretty text. |
| `--no-color` | Disable ANSI colors. Auto-disabled when stdout is not a TTY. |
| `-h`, `--help` | Show usage. |
| `-v`, `--version` | Show version. |

### Examples

**Inspect an attestation response from devtools:**

```sh
passkey-inspect 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViY...'
```

**Inspect authenticator data from an assertion:**

```sh
passkey-inspect --type=authdata 'SZYN5e...'
```

**Inspect clientDataJSON piped from a curl response:**

```sh
curl -s ...  | jq -r '.response.clientDataJSON' | passkey-inspect --type=client
```

**Machine-readable output for a script:**

```sh
passkey-inspect --json --no-color attestation.b64 | jq '.parsed.authData.flags'
```

**Decode a whole credential** — paste the entire object your frontend sends to the server (as produced by `PublicKeyCredential.toJSON()` or `@github/webauthn-json`) and every embedded field is decoded at once:

```sh
passkey-inspect registration-response.json
```

`passkey-inspect` detects whether it is a registration (attestation) or authentication (assertion) response, decodes the `clientDataJSON` and the `attestationObject` / `authenticatorData` together, and surfaces the `signature` and `userHandle`. No more copying three fields out of one payload.

## Library usage

```js
import { parse, parseAttestationObject, parseAuthData, parseClientDataJSON } from 'passkey-inspect';

// Auto-detect from a base64url / base64 / hex / JSON string
const { type, parsed } = parse(attestationObjectB64u);

// Or call a parser directly with Uint8Array bytes
const authData = parseAuthData(bytes);
console.log(authData.flags.UV, authData.signCount);
```

All parsers accept `Uint8Array` and return plain JS objects. CBOR maps round-trip as `Map` instances inside the auxiliary fields, so non-string keys (COSE labels, for example) are preserved.

### Exported API

| Export | Description |
|--------|-------------|
| `parse(input)` | Auto-detect from a `string`, `Uint8Array`, or serialized credential object. Returns `{ type, parsed, inputEncoding, byteLength }`. |
| `detectAndParse(bytes)` | Auto-detect from `Uint8Array`. |
| `parseCredential(input)` | Decode a whole serialized `PublicKeyCredential` (object or JSON string). Returns the ceremony type and every decoded part. |
| `isCredentialJSON(obj)` | Test whether an object looks like a serialized credential response. |
| `parseAttestationObject(bytes)` | Decode a CBOR `attestationObject`. |
| `parseAuthData(bytes)` | Decode `authenticatorData`. |
| `parseClientDataJSON(bytes)` | Decode `clientDataJSON` with spec-compliance warnings. |
| `parseCoseKey(map)` | Decode a COSE_Key CBOR map. |
| `parseFlags(byte)` | Decode the authenticator-data flags byte. |
| `lookupAaguid(uuid)` / `AAGUID_NAMES` | Resolve a known AAGUID to an authenticator model name. |
| `b64uToBytes`, `b64ToBytes`, `hexToBytes`, `bytesToB64u`, `bytesToHex`, `autoDecode` | Encoding helpers. |
| `TYPES` | `{ CLIENT_DATA_JSON, ATTESTATION_OBJECT, AUTH_DATA }`. |

## What it parses

- **`attestationObject`** — CBOR map with `fmt`, `attStmt`, `authData`. Surfaces the format (`none`, `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, `apple`, `apple-appattest`) and warns on unknown formats or spec violations (e.g. non-empty `attStmt` with `fmt=none`).
- **`authenticatorData`** — RP ID hash, flags byte (UP, UV, BE, BS, AT, ED), signature counter, attested credential data (AAGUID, credential ID, COSE public key), and extension data. Known AAGUIDs are resolved to a model name (Google Password Manager, iCloud Keychain, YubiKey, Windows Hello, and more).
- **serialized credentials** — the full JSON object from `navigator.credentials.create()` / `.get()`. `passkey-inspect` decodes the `clientDataJSON` and `attestationObject` / `authenticatorData` in one pass and reports the ceremony type, signature, and user handle.
- **`clientDataJSON`** — `type`, `challenge`, `origin`, `crossOrigin`, `topOrigin`, with warnings when fields are missing, wrongly encoded, or have an unexpected `type`.
- **COSE keys** — EC2 (P-256/P-384/P-521), OKP (Ed25519/Ed448/X25519/X448), RSA. Recognises ES256/ES384/ES512, EdDSA, PS256/384/512, RS256/384/512.

## Security and privacy

`passkey-inspect` is a parser, not a validator. It does not verify signatures, attestation chains, or that the AAGUID matches a metadata service entry. Use it as a debugging tool, not as a substitute for relying-party verification logic. See [Backend Verification & Secure Credential Storage](https://www.passkeywebauthn.com/backend-verification-secure-credential-storage/) for what real verification needs to do.

All decoding happens in-process; no network requests are ever made.

## Related tools

`passkey-inspect` is part of a small set of open-source WebAuthn tools:

- [webauthn-ceremony-inspector](https://github.com/passkeywebauthn/webauthn-ceremony-inspector) — a browser DevTools panel that captures and decodes live ceremonies (it reuses this project's decoder).
- [passkey-fixture-generator](https://github.com/passkeywebauthn/passkey-fixture-generator) — deterministic, valid registration/authentication fixtures for testing your backend verification.
- [rp-id-doctor](https://github.com/passkeywebauthn/rp-id-doctor) — validate your `rpId`, origins, and `.well-known/webauthn` configuration in CI.
- [authenticator-support-matrix](https://github.com/passkeywebauthn/authenticator-support-matrix) — a filterable feature matrix of platform and roaming authenticators.

## Development

```sh
git clone https://github.com/passkeywebauthn/passkey-inspect.git
cd passkey-inspect
npm test
```

Tests use Node's built-in `node:test` runner and ship with hand-built fixtures so they are completely reproducible.

## License

MIT © passkeywebauthn

---

**Learn more about WebAuthn and passkeys at [passkeywebauthn.com](https://www.passkeywebauthn.com).**
