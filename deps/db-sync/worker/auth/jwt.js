"use strict";

const crypto = require("node:crypto");
const { AuthError } = require("./errors");
const b64 = require("./base64url");

const ALG = "RS256";

function encodeJson(value) {
  return b64.encode(JSON.stringify(value));
}

function decodeJson(part) {
  let parsed;
  try {
    parsed = JSON.parse(b64.decode(part).toString("utf8"));
  } catch {
    throw new AuthError("malformed_token", "malformed token", 401);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AuthError("malformed_token", "malformed token", 401);
  }
  return parsed;
}

function decodeToken(token) {
  if (typeof token !== "string") {
    throw new AuthError("malformed_token", "malformed token", 401);
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new AuthError("malformed_token", "malformed token", 401);
  }
  const [headerPart, payloadPart, signaturePart] = parts;
  let signature;
  try {
    signature = b64.decode(signaturePart);
  } catch {
    throw new AuthError("malformed_token", "malformed token", 401);
  }
  return {
    header: decodeJson(headerPart),
    payload: decodeJson(payloadPart),
    signingInput: `${headerPart}.${payloadPart}`,
    signature,
  };
}

/**
 * Mint a compact JWS. `signer.signingKey()` resolves to `{kid, sign}` where
 * `sign(buffer)` returns the PKCS#1 v1.5 SHA-256 signature bytes.
 */
async function mintToken({ signer, claims }) {
  const { kid, sign } = await signer.signingKey();
  const header = { alg: ALG, typ: "JWT", kid };
  const signingInput = `${encodeJson(header)}.${encodeJson(claims)}`;
  const signature = await sign(Buffer.from(signingInput, "utf8"));
  return `${signingInput}.${b64.encode(signature)}`;
}

function jwkToPublicKey(jwk) {
  return crypto.createPublicKey({
    key: { kty: "RSA", n: jwk.n, e: jwk.e },
    format: "jwk",
  });
}

/**
 * Verify a token against a fixed key set. Throws AuthError for any token that
 * must be refused; returns the payload otherwise.
 */
function verifyToken(token, { issuer, audience, keys, nowS = Math.floor(Date.now() / 1000), skewS = 60 }) {
  const { header, payload, signingInput, signature } = decodeToken(token);
  if (header.alg !== ALG) {
    throw new AuthError("unsupported_alg", "unsupported token algorithm", 401);
  }
  if (typeof header.kid !== "string" || header.kid === "") {
    throw new AuthError("unknown_kid", "token key id missing", 401);
  }
  const key = keys.find((candidate) => candidate.kid === header.kid);
  if (!key) {
    throw new AuthError("unknown_kid", "token key id unknown", 401);
  }
  const valid = crypto.verify("RSA-SHA256", Buffer.from(signingInput, "utf8"), jwkToPublicKey(key), signature);
  if (!valid) {
    throw new AuthError("bad_signature", "token signature invalid", 401);
  }
  if (payload.iss !== issuer) {
    throw new AuthError("bad_issuer", "token issuer mismatch", 401);
  }
  if (payload.aud !== audience) {
    throw new AuthError("bad_audience", "token audience mismatch", 401);
  }
  if (typeof payload.exp !== "number" || payload.exp <= nowS - skewS) {
    throw new AuthError("expired", "token expired", 401);
  }
  if (typeof payload.nbf === "number" && payload.nbf > nowS + skewS) {
    throw new AuthError("not_yet_valid", "token not yet valid", 401);
  }
  if (typeof payload.sub !== "string" || payload.sub === "") {
    throw new AuthError("missing_subject", "token subject missing", 401);
  }
  return payload;
}

/**
 * A verifier bound to a signer's public keys. Unknown key ids trigger one key
 * refresh so a rotated Transit key is picked up without a restart. `verify`
 * resolves to the payload, or `null` when the token must be refused; it rejects
 * only when the key set cannot be loaded.
 */
function createVerifier({ signer, issuer, audience, now = Date.now, keyTtlMs = 10 * 60 * 1000 }) {
  let cached = null;

  async function keys(force) {
    const t = now();
    if (!force && cached && t - cached.fetchedAt < keyTtlMs) {
      return cached.keys;
    }
    const fresh = await signer.publicKeys(force);
    cached = { keys: fresh, fetchedAt: t };
    return fresh;
  }

  async function verify(token) {
    const nowS = Math.floor(now() / 1000);
    try {
      return verifyToken(token, { issuer, audience, keys: await keys(false), nowS });
    } catch (error) {
      if (error instanceof AuthError && error.code === "unknown_kid") {
        try {
          return verifyToken(token, { issuer, audience, keys: await keys(true), nowS });
        } catch (retryError) {
          if (retryError instanceof AuthError) return null;
          throw retryError;
        }
      }
      if (error instanceof AuthError) return null;
      throw error;
    }
  }

  return { verify, keys };
}

module.exports = { ALG, decodeToken, mintToken, verifyToken, createVerifier, jwkToPublicKey };
