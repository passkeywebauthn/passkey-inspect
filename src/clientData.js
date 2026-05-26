// Parses WebAuthn `clientDataJSON`. It is a UTF-8 JSON document; per the
// spec the relying party MUST validate `type`, `challenge`, and `origin`.

export function parseClientDataJSON(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('parseClientDataJSON expects Uint8Array');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    throw new Error(`clientDataJSON is not valid JSON: ${e.message}`);
  }
  const out = {
    raw: json,
    text,
    type: json.type,
    challenge: json.challenge,
    origin: json.origin,
    crossOrigin: json.crossOrigin ?? false,
  };
  if (json.topOrigin) out.topOrigin = json.topOrigin;
  if (json.tokenBinding) out.tokenBinding = json.tokenBinding;

  const warnings = [];
  if (out.type !== 'webauthn.create' && out.type !== 'webauthn.get') {
    warnings.push(`unexpected type "${out.type}" — expected "webauthn.create" or "webauthn.get"`);
  }
  if (typeof out.challenge !== 'string' || out.challenge.length === 0) {
    warnings.push('challenge missing or empty');
  } else if (!/^[A-Za-z0-9_-]+$/.test(out.challenge)) {
    warnings.push('challenge is not base64url-encoded (per the spec it MUST be)');
  }
  if (typeof out.origin !== 'string' || !/^https?:\/\//.test(out.origin)) {
    warnings.push('origin missing or not an http(s) URL');
  }
  if (warnings.length) out.warnings = warnings;

  return out;
}
