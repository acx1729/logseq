"use strict";

const { AuthError } = require("./errors");
const { createVerifier, mintToken } = require("./jwt");
const pkce = require("./pkce");
const { renderSignInPage } = require("./page");
const { createRateLimiter } = require("./ratelimit");
const { shortAddress, verifySiweSignIn } = require("./siwe");

const SCOPE = "logseq/read logseq/write";
const STATE_RE = /^[\x21-\x7e]{1,512}$/;
const DEFAULT_RATE_LIMITS = {
  nonce: { limit: 120, windowMs: 60 * 1000 },
  siwe: { limit: 30, windowMs: 60 * 1000 },
  token: { limit: 30, windowMs: 60 * 1000 },
};

function requireString(value, code, message) {
  if (typeof value !== "string" || value === "") {
    throw new AuthError(code, message, 400);
  }
  return value;
}

/**
 * Parse a request body as JSON or as application/x-www-form-urlencoded into a
 * plain object of string values. Everything else is refused.
 */
function parseBody(contentType, text) {
  const type = String(contentType || "").split(";")[0].trim().toLowerCase();
  if (type === "application/x-www-form-urlencoded") {
    const params = new URLSearchParams(text || "");
    const body = {};
    for (const [key, value] of params) body[key] = value;
    return body;
  }
  if (type === "application/json" || type === "") {
    if (!text) return {};
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new AuthError("invalid_request", "request body is not valid JSON", 400);
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new AuthError("invalid_request", "request body must be a JSON object", 400);
    }
    return parsed;
  }
  throw new AuthError("unsupported_media_type", "unsupported request content type", 415);
}

function toSet(values, transform) {
  return new Set((values || []).map(transform));
}

/**
 * The sign-in service behind /auth/*. Holds no request-handling code: the
 * adapter maps its results and AuthErrors to HTTP responses.
 *
 * config: { issuer, audience, tokenTtlS, siweDomains, siweChainIds, redirectUris,
 *           siweStatement, appName, nonceTtlMs, codeTtlMs, rateLimits }
 */
function createAuthService({ config, signer, store, now = Date.now }) {
  const issuer = requireString(config.issuer, "config", "issuer is required");
  const audience = requireString(config.audience, "config", "audience is required");
  const tokenTtlS = Number(config.tokenTtlS);
  if (!Number.isInteger(tokenTtlS) || tokenTtlS <= 0) {
    throw new Error("token ttl must be a positive integer of seconds");
  }
  const domains = toSet(config.siweDomains, (domain) => String(domain).toLowerCase());
  if (domains.size === 0) {
    throw new Error("at least one SIWE domain is required");
  }
  const chainIds = config.siweChainIds && config.siweChainIds.length ? toSet(config.siweChainIds, Number) : null;
  const redirectUris = toSet(config.redirectUris, String);
  const statement = config.siweStatement || "Sign in to Logseq";
  const appName = config.appName || "Logseq";
  const nonceTtlMs = config.nonceTtlMs || 5 * 60 * 1000;
  const codeTtlMs = config.codeTtlMs || 5 * 60 * 1000;
  const rateLimits = Object.assign({}, DEFAULT_RATE_LIMITS, config.rateLimits || {});
  const limiters = {};
  for (const [name, spec] of Object.entries(rateLimits)) {
    limiters[name] = createRateLimiter({ limit: spec.limit, windowMs: spec.windowMs, now });
  }
  const verifier = createVerifier({ signer, issuer, audience, now });

  function checkRate(kind, ip) {
    if (typeof ip === "string" && ip !== "" && !limiters[kind].allow(`${kind}:${ip}`)) {
      throw new AuthError("rate_limited", "too many requests", 429);
    }
  }

  function requireRedirectUri(value) {
    const uri = requireString(value, "invalid_redirect_uri", "redirect_uri is required");
    if (!redirectUris.has(uri)) {
      throw new AuthError("invalid_redirect_uri", "redirect_uri is not allowed", 400);
    }
    return uri;
  }

  function requireChallenge(challenge, method) {
    if (method !== "S256") {
      throw new AuthError("invalid_request", "code_challenge_method must be S256", 400);
    }
    if (!pkce.validChallenge(challenge)) {
      throw new AuthError("invalid_request", "code_challenge is malformed", 400);
    }
    return challenge;
  }

  function userForAddress(address) {
    return { sub: address, username: shortAddress(address) };
  }

  async function issue(user) {
    const iat = Math.floor(now() / 1000);
    const exp = iat + tokenTtlS;
    const claims = { iss: issuer, aud: audience, sub: user.sub, iat, exp, username: user.username, scope: SCOPE };
    const token = await mintToken({ signer, claims });
    return { token, claims, expiresIn: tokenTtlS };
  }

  function issueNonce({ ip } = {}) {
    checkRate("nonce", ip);
    const t = now();
    store.prune(t);
    const nonce = pkce.randomNonce();
    store.putNonce(nonce, t, t + nonceTtlMs);
    return { nonce, expires_at: Math.floor((t + nonceTtlMs) / 1000) };
  }

  /**
   * Verify a signed message. With a PKCE challenge and redirect URI the result
   * is a one-time code for /auth/token; without them it is a token directly.
   */
  async function signIn({ ip, body } = {}) {
    checkRate("siwe", ip);
    const input = body || {};
    const identity = await verifySiweSignIn({
      message: input.message,
      signature: input.signature,
      domains,
      chainIds,
      nowMs: now(),
    });
    if (!store.consumeNonce(identity.nonce, now())) {
      throw new AuthError("invalid_nonce", "nonce is unknown, already used or expired", 400);
    }
    const user = userForAddress(identity.address);
    const codeFlow = input.code_challenge !== undefined || input.redirect_uri !== undefined;
    if (codeFlow) {
      const redirectUri = requireRedirectUri(input.redirect_uri);
      const challenge = requireChallenge(input.code_challenge, input.code_challenge_method);
      const code = pkce.randomCode();
      const t = now();
      store.putCode(pkce.hashCode(code), { userId: user.sub, codeChallenge: challenge, redirectUri }, t, t + codeTtlMs);
      return { kind: "code", code, user, chainId: identity.chainId };
    }
    const issued = await issue(user);
    return { kind: "token", token: issued.token, expiresIn: issued.expiresIn, claims: issued.claims, user, chainId: identity.chainId };
  }

  /** OAuth-style authorization-code exchange with PKCE, as the CLI performs it. */
  async function exchangeCode({ ip, body } = {}) {
    checkRate("token", ip);
    const input = body || {};
    if (input.grant_type !== "authorization_code") {
      throw new AuthError("unsupported_grant_type", "grant_type must be authorization_code", 400);
    }
    if (input.client_id !== undefined && input.client_id !== audience) {
      throw new AuthError("invalid_client", "client_id is not accepted", 400);
    }
    const code = requireString(input.code, "invalid_grant", "code is required");
    const record = store.consumeCode(pkce.hashCode(code), now());
    if (!record) {
      throw new AuthError("invalid_grant", "code is unknown, already used or expired", 400);
    }
    if (record.redirectUri !== input.redirect_uri) {
      throw new AuthError("invalid_grant", "redirect_uri does not match the authorization request", 400);
    }
    if (!pkce.verifierMatches(input.code_verifier, record.codeChallenge)) {
      throw new AuthError("invalid_grant", "code_verifier does not match the code_challenge", 400);
    }
    const issued = await issue(userForAddress(record.userId));
    return { token: issued.token, expiresIn: issued.expiresIn, claims: issued.claims };
  }

  function tokenResponse(issued) {
    return {
      token_type: "Bearer",
      access_token: issued.token,
      id_token: issued.token,
      expires_in: issued.expiresIn,
      scope: SCOPE,
    };
  }

  /** Validate the authorize-request query and render the hosted page. */
  function signInPage(query) {
    const input = query || {};
    const state = requireString(input.state, "invalid_request", "state is required");
    if (!STATE_RE.test(state)) {
      throw new AuthError("invalid_request", "state is malformed", 400);
    }
    if (input.response_type !== undefined && input.response_type !== "code") {
      throw new AuthError("invalid_request", "response_type must be code", 400);
    }
    if (input.client_id !== undefined && input.client_id !== audience) {
      throw new AuthError("invalid_client", "client_id is not accepted", 400);
    }
    const redirectUri = requireRedirectUri(input.redirect_uri);
    const codeChallenge = requireChallenge(input.code_challenge, input.code_challenge_method);
    return renderSignInPage({ appName, statement, state, codeChallenge, redirectUri });
  }

  async function jwks() {
    return { keys: await signer.publicKeys(false) };
  }

  return {
    issueNonce,
    signIn,
    exchangeCode,
    tokenResponse,
    signInPage,
    jwks,
    verify: verifier.verify,
    audience,
    issuer,
  };
}

module.exports = { createAuthService, parseBody, SCOPE };
