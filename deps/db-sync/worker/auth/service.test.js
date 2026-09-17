"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const Database = require("better-sqlite3");
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");
const { AuthError } = require("./errors");
const pkce = require("./pkce");
const { createAuthService, parseBody } = require("./service");
const { createSiweMessage } = require("./siwe");
const { AUTH_MIGRATIONS, createAuthStore } = require("./store");
const { testSigner } = require("./test_helpers");

const ISSUER = "http://localhost:8787";
const REDIRECT = "http://localhost:8765/auth/callback";
const account = privateKeyToAccount(generatePrivateKey());

function openDb() {
  const db = new Database(":memory:");
  for (const migration of AUTH_MIGRATIONS) {
    for (const statement of migration.statements) db.exec(statement);
  }
  return db;
}

function makeService(overrides = {}) {
  let t = 1_700_000_000_000;
  const now = () => t;
  const service = createAuthService({
    config: {
      issuer: ISSUER,
      audience: "logseq-sync",
      tokenTtlS: 2592000,
      siweDomains: ["localhost:8787"],
      siweChainIds: [1],
      redirectUris: ["logseq://auth/callback", REDIRECT],
      appName: "Logseq",
      ...overrides,
    },
    signer: testSigner(),
    store: createAuthStore(openDb()),
    now,
  });
  return { service, advance: (ms) => { t += ms; }, now };
}

async function signedMessage(nonce, nowMs, overrides = {}) {
  const issuedAt = new Date(nowMs);
  const message = createSiweMessage({
    address: account.address,
    chainId: 1,
    domain: "localhost:8787",
    nonce,
    uri: "http://localhost:8787/auth/siwe/start",
    version: "1",
    statement: "Sign in to Logseq",
    issuedAt,
    expirationTime: new Date(issuedAt.getTime() + 5 * 60 * 1000),
    ...overrides,
  });
  return { message, signature: await account.signMessage({ message }) };
}

test("direct flow: nonce, signed message, token, verify", async () => {
  const { service, now } = makeService();
  const { nonce } = service.issueNonce({ ip: "10.0.0.1" });
  assert.match(nonce, /^[0-9a-f]{32}$/);
  const body = await signedMessage(nonce, now());
  const result = await service.signIn({ ip: "10.0.0.1", body });
  assert.equal(result.kind, "token");
  assert.equal(result.user.sub, account.address.toLowerCase());
  assert.equal(result.user.username.slice(0, 6), account.address.slice(0, 6));
  assert.equal(result.expiresIn, 2592000);
  const claims = await service.verify(result.token);
  assert.equal(claims.sub, account.address.toLowerCase());
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.aud, "logseq-sync");
  assert.equal(claims.scope, "logseq/read logseq/write");
  assert.equal(claims.exp - claims.iat, 2592000);
  assert.equal(await service.verify("forged"), null);
  const response = service.tokenResponse(result);
  assert.deepEqual(Object.keys(response).sort(), ["access_token", "expires_in", "id_token", "scope", "token_type"]);
});

test("a nonce cannot be used twice, an unknown nonce is refused, and expired nonces are refused", async () => {
  const { service, now, advance } = makeService();
  const { nonce } = service.issueNonce({});
  const body = await signedMessage(nonce, now());
  await service.signIn({ body });
  await assert.rejects(() => service.signIn({ body }), (e) => e instanceof AuthError && e.code === "invalid_nonce");
  const unknown = await signedMessage("ffffffffffffffffffffffffffffffff", now());
  await assert.rejects(() => service.signIn({ body: unknown }), (e) => e.code === "invalid_nonce");
  const { nonce: late } = service.issueNonce({});
  advance(4 * 60 * 1000);
  const lateBody = await signedMessage(late, now());
  advance(2 * 60 * 1000);
  await assert.rejects(() => service.signIn({ body: lateBody }), (e) => e.code === "siwe_message_expired" || e.code === "invalid_nonce");
});

test("code flow: hosted page parameters, code, PKCE exchange", async () => {
  const { service, now } = makeService();
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = pkce.challengeForVerifier(verifier);
  const page = service.signInPage({
    response_type: "code",
    client_id: "logseq-sync",
    state: "xyz",
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  assert.match(page.html, /siwe-params/);
  const { nonce } = service.issueNonce({});
  const body = await signedMessage(nonce, now());
  const result = await service.signIn({ body: { ...body, code_challenge: challenge, code_challenge_method: "S256", redirect_uri: REDIRECT } });
  assert.equal(result.kind, "code");
  assert.match(result.code, /^[A-Za-z0-9_-]{43}$/);
  await assert.rejects(
    () => service.exchangeCode({ body: { grant_type: "authorization_code", code: result.code, redirect_uri: REDIRECT, code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-wrong" } }),
    (e) => e.code === "invalid_grant",
  );
  const { nonce: nonce2 } = service.issueNonce({});
  const body2 = await signedMessage(nonce2, now());
  const result2 = await service.signIn({ body: { ...body2, code_challenge: challenge, code_challenge_method: "S256", redirect_uri: REDIRECT } });
  const issued = await service.exchangeCode({
    body: { grant_type: "authorization_code", code: result2.code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: "logseq-sync" },
  });
  const claims = await service.verify(issued.token);
  assert.equal(claims.sub, account.address.toLowerCase());
  await assert.rejects(
    () => service.exchangeCode({ body: { grant_type: "authorization_code", code: result2.code, redirect_uri: REDIRECT, code_verifier: verifier } }),
    (e) => e.code === "invalid_grant",
  );
});

test("code flow refuses unlisted redirect URIs, bad challenges, wrong clients and grant types", async () => {
  const { service, now } = makeService();
  const challenge = pkce.challengeForVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
  assert.throws(() => service.signInPage({ state: "s", redirect_uri: "https://evil.example/cb", code_challenge: challenge, code_challenge_method: "S256" }), (e) => e.code === "invalid_redirect_uri");
  assert.throws(() => service.signInPage({ state: "s", redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "plain" }), (e) => e.code === "invalid_request");
  assert.throws(() => service.signInPage({ state: "s", redirect_uri: REDIRECT, code_challenge: "short", code_challenge_method: "S256" }), (e) => e.code === "invalid_request");
  assert.throws(() => service.signInPage({ state: "", redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256" }), (e) => e.code === "invalid_request");
  assert.throws(() => service.signInPage({ state: "s", client_id: "other", redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: "S256" }), (e) => e.code === "invalid_client");
  const { nonce } = service.issueNonce({});
  const body = await signedMessage(nonce, now());
  await assert.rejects(() => service.signIn({ body: { ...body, code_challenge: challenge, code_challenge_method: "S256", redirect_uri: "https://evil.example/cb" } }), (e) => e.code === "invalid_redirect_uri");
  await assert.rejects(() => service.exchangeCode({ body: { grant_type: "client_credentials" } }), (e) => e.code === "unsupported_grant_type");
  await assert.rejects(() => service.exchangeCode({ body: { grant_type: "authorization_code", client_id: "nope", code: "c" } }), (e) => e.code === "invalid_client");
});

test("a code exchanged with a different redirect_uri is refused", async () => {
  const { service, now } = makeService();
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = pkce.challengeForVerifier(verifier);
  const { nonce } = service.issueNonce({});
  const body = await signedMessage(nonce, now());
  const result = await service.signIn({ body: { ...body, code_challenge: challenge, code_challenge_method: "S256", redirect_uri: REDIRECT } });
  await assert.rejects(
    () => service.exchangeCode({ body: { grant_type: "authorization_code", code: result.code, redirect_uri: "logseq://auth/callback", code_verifier: verifier } }),
    (e) => e.code === "invalid_grant",
  );
});

test("rate limits apply per client address and per endpoint", async () => {
  const { service } = makeService({ rateLimits: { nonce: { limit: 2, windowMs: 60000 } } });
  service.issueNonce({ ip: "1.1.1.1" });
  service.issueNonce({ ip: "1.1.1.1" });
  assert.throws(() => service.issueNonce({ ip: "1.1.1.1" }), (e) => e.code === "rate_limited" && e.status === 429);
  assert.doesNotThrow(() => service.issueNonce({ ip: "2.2.2.2" }));
  assert.doesNotThrow(() => service.issueNonce({}));
});

test("jwks lists the signer's public keys", async () => {
  const { service } = makeService();
  const { keys } = await service.jwks();
  assert.equal(keys.length, 1);
  assert.equal(keys[0].alg, "RS256");
});

test("service configuration is validated", () => {
  assert.throws(() => makeService({ siweDomains: [] }), /SIWE domain/);
  assert.throws(() => makeService({ tokenTtlS: 0 }), /ttl/);
  assert.throws(() => makeService({ issuer: "" }), (e) => e instanceof AuthError);
});

test("parseBody handles JSON and form bodies and refuses others", () => {
  assert.deepEqual(parseBody("application/json", '{"a":1}'), { a: 1 });
  assert.deepEqual(parseBody("application/json; charset=utf-8", ""), {});
  assert.deepEqual(parseBody("application/x-www-form-urlencoded", "grant_type=authorization_code&code=a%20b"), { grant_type: "authorization_code", code: "a b" });
  assert.throws(() => parseBody("application/json", "[1]"), (e) => e.code === "invalid_request");
  assert.throws(() => parseBody("application/json", "{"), (e) => e.code === "invalid_request");
  assert.throws(() => parseBody("text/plain", "x"), (e) => e.code === "unsupported_media_type" && e.status === 415);
});
