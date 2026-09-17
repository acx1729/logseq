"use strict";

const { AuthError } = require("./errors");
const { createVerifier, mintToken } = require("./jwt");
const { createRateLimiter } = require("./ratelimit");
const { randomNonce, shortAddress, verifySiweSignIn } = require("./siwe");

const SCOPE = "logseq/read logseq/write";
const USERNAME_MAX_LENGTH = 64;
const USERNAME_RE = /^[^\p{Cc}\u2028\u2029]{1,64}$/u;
const NONCE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_RATE_LIMITS = {
  nonce: { limit: 120, windowMs: 60 * 1000 },
  siwe: { limit: 30, windowMs: 60 * 1000 },
};

function configString(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`auth config: ${name} is required`);
  }
  return value;
}

function requireString(value, code, message) {
  if (typeof value !== "string" || value === "") {
    throw new AuthError(code, message, 400);
  }
  return value;
}

/** Parse a JSON request body into a plain object. Everything else is refused. */
function parseBody(contentType, text) {
  const type = String(contentType || "").split(";")[0].trim().toLowerCase();
  if (type !== "application/json") {
    throw new AuthError("unsupported_media_type", "request body must be application/json", 415);
  }
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

/**
 * The display name a sign-in may carry: absent, or 1 to 64 characters with
 * surrounding whitespace removed and no control characters.
 */
function normalizeUsername(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw new AuthError("invalid_request", "username must be a string", 400);
  }
  const trimmed = value.trim();
  if (!USERNAME_RE.test(trimmed)) {
    throw new AuthError(
      "invalid_username",
      `username must be 1 to ${USERNAME_MAX_LENGTH} characters without control characters`,
      400,
    );
  }
  return trimmed;
}

function parseChainIds(values) {
  const ids = new Set();
  for (const value of values || []) {
    const id = Number(value);
    if (!Number.isInteger(id) || id <= 0) {
      throw new Error(`auth config: chain id ${JSON.stringify(value)} is not a positive integer`);
    }
    ids.add(id);
  }
  if (ids.size === 0) {
    throw new Error("auth config: at least one SIWE chain id is required");
  }
  return ids;
}

function parseRpcUrls(value, chainIds) {
  const urls = {};
  for (const [key, url] of Object.entries(value || {})) {
    const id = Number(key);
    if (!chainIds.has(id)) {
      throw new Error(`auth config: rpc url for chain ${key} which is not an accepted chain id`);
    }
    if (typeof url !== "string" || !/^(https?|wss?):\/\//.test(url)) {
      throw new Error(`auth config: rpc url for chain ${key} must be an http(s) or ws(s) URL`);
    }
    urls[String(id)] = url;
  }
  return urls;
}

/**
 * The sign-in service behind /auth/*. Holds no request-handling code: the
 * adapter maps its results and AuthErrors to HTTP responses.
 *
 * config: { issuer, audience, tokenTtlS, siweDomains, siweChainIds, siweStatement,
 *           appName, rpcUrls, walletConnectProjectId, nonceTtlMs, rateLimits }
 */
function createAuthService({ config, signer, store, now = Date.now }) {
  const issuer = configString(config.issuer, "issuer");
  const audience = configString(config.audience, "audience");
  const tokenTtlS = Number(config.tokenTtlS);
  if (!Number.isInteger(tokenTtlS) || tokenTtlS <= 0) {
    throw new Error("auth config: token ttl must be a positive integer of seconds");
  }
  const domains = new Set((config.siweDomains || []).map((domain) => String(domain).toLowerCase()));
  if (domains.size === 0) {
    throw new Error("auth config: at least one SIWE domain is required");
  }
  const chainIds = parseChainIds(config.siweChainIds);
  const statement = configString(config.siweStatement, "siweStatement");
  const appName = configString(config.appName, "appName");
  const rpcUrls = parseRpcUrls(config.rpcUrls, chainIds);
  const walletConnectProjectId = config.walletConnectProjectId === undefined || config.walletConnectProjectId === null
    ? null
    : configString(config.walletConnectProjectId, "walletConnectProjectId");
  const nonceTtlMs = config.nonceTtlMs || NONCE_TTL_MS;
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

  /** What a client needs to build its wallet setup and sign-in message. */
  function clientConfig() {
    return {
      issuer,
      app_name: appName,
      statement,
      chain_ids: [...chainIds],
      rpc_urls: Object.assign({}, rpcUrls),
      walletconnect_project_id: walletConnectProjectId,
    };
  }

  function issueNonce({ ip } = {}) {
    checkRate("nonce", ip);
    const t = now();
    store.prune(t);
    const nonce = randomNonce();
    store.putNonce(nonce, t, t + nonceTtlMs);
    return { nonce, expires_at: Math.floor((t + nonceTtlMs) / 1000) };
  }

  /**
   * Verify a signed message and consume its nonce. Resolves to the signer's
   * address, the chain it signed on, the display name the request carried
   * (null when none) and the name to give a first-time user.
   */
  async function verifySignIn({ ip, body } = {}) {
    checkRate("siwe", ip);
    const input = body || {};
    const username = normalizeUsername(input.username);
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
    return {
      address: identity.address,
      chainId: identity.chainId,
      username,
      defaultUsername: shortAddress(identity.address),
    };
  }

  /** Mint the session token of a signed-in user. */
  async function issueToken({ sub, username }) {
    if (typeof sub !== "string" || sub === "" || typeof username !== "string" || username === "") {
      throw new Error("issueToken needs the user's address and display name");
    }
    const iat = Math.floor(now() / 1000);
    const exp = iat + tokenTtlS;
    const claims = { iss: issuer, aud: audience, sub, iat, exp, username, scope: SCOPE };
    const token = await mintToken({ signer, claims });
    return { token, claims, expiresIn: tokenTtlS };
  }

  function tokenResponse(issued) {
    return {
      token_type: "Bearer",
      access_token: issued.token,
      expires_in: issued.expiresIn,
      scope: SCOPE,
    };
  }

  async function jwks() {
    return { keys: await signer.publicKeys(false) };
  }

  return {
    clientConfig,
    issueNonce,
    verifySignIn,
    issueToken,
    tokenResponse,
    jwks,
    verify: verifier.verify,
    audience,
    issuer,
  };
}

module.exports = { createAuthService, normalizeUsername, parseBody, SCOPE, USERNAME_MAX_LENGTH };
