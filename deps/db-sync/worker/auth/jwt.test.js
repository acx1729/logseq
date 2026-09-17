"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { AuthError } = require("./errors");
const { createVerifier, decodeToken, mintToken, verifyToken } = require("./jwt");
const { testSigner } = require("./test_helpers");

const ISS = "https://sync.example.test";
const AUD = "logseq-sync";

async function mint(signer, overrides = {}) {
  const iat = Math.floor(Date.now() / 1000);
  const claims = { iss: ISS, aud: AUD, sub: "0xabc", iat, exp: iat + 3600, ...overrides };
  return mintToken({ signer, claims });
}

test("mintToken produces an RS256 token that verifyToken accepts", async () => {
  const signer = testSigner();
  const token = await mint(signer);
  const { header } = decodeToken(token);
  assert.equal(header.alg, "RS256");
  assert.equal(header.typ, "JWT");
  const keys = await signer.publicKeys();
  assert.equal(header.kid, keys[0].kid);
  const payload = verifyToken(token, { issuer: ISS, audience: AUD, keys });
  assert.equal(payload.sub, "0xabc");
});

test("verifyToken refuses tampered payloads, wrong issuer, wrong audience and expiry", async () => {
  const signer = testSigner();
  const keys = await signer.publicKeys();
  const token = await mint(signer);
  const [h, p, s] = token.split(".");
  const forgedPayload = Buffer.from(JSON.stringify({ iss: ISS, aud: AUD, sub: "0xevil", exp: 9999999999 })).toString("base64url");
  assert.throws(() => verifyToken(`${h}.${forgedPayload}.${s}`, { issuer: ISS, audience: AUD, keys }), (e) => e instanceof AuthError && e.code === "bad_signature");
  assert.throws(() => verifyToken(token, { issuer: "https://other", audience: AUD, keys }), (e) => e.code === "bad_issuer");
  assert.throws(() => verifyToken(token, { issuer: ISS, audience: "other", keys }), (e) => e.code === "bad_audience");
  const expired = await mint(signer, { exp: Math.floor(Date.now() / 1000) - 3600 });
  assert.throws(() => verifyToken(expired, { issuer: ISS, audience: AUD, keys }), (e) => e.code === "expired");
  assert.throws(() => verifyToken("not.a.token", { issuer: ISS, audience: AUD, keys }), (e) => e.code === "malformed_token");
  assert.throws(() => verifyToken(token, { issuer: ISS, audience: AUD, keys: [] }), (e) => e.code === "unknown_kid");
  const noneHeader = Buffer.from(JSON.stringify({ alg: "none", kid: keys[0].kid })).toString("base64url");
  assert.throws(() => verifyToken(`${noneHeader}.${p}.`, { issuer: ISS, audience: AUD, keys }), (e) => e.code === "unsupported_alg");
});

test("verifyToken rejects tokens signed by another key with the same kid", async () => {
  const signer = testSigner();
  const other = testSigner();
  const keys = await signer.publicKeys();
  const otherToken = await mint(other);
  const [, p, s] = otherToken.split(".");
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: keys[0].kid })).toString("base64url");
  assert.throws(() => verifyToken(`${header}.${p}.${s}`, { issuer: ISS, audience: AUD, keys }), (e) => e.code === "bad_signature");
});

test("createVerifier returns null for refused tokens and refreshes keys on an unknown kid", async () => {
  const first = testSigner();
  const second = testSigner();
  let current = first;
  let fetches = 0;
  const rotating = {
    async signingKey() {
      return current.signingKey();
    },
    async publicKeys() {
      fetches += 1;
      return current.publicKeys();
    },
  };
  const verifier = createVerifier({ signer: rotating, issuer: ISS, audience: AUD });
  const token1 = await mint(first);
  assert.equal((await verifier.verify(token1)).sub, "0xabc");
  assert.equal(await verifier.verify("garbage"), null);
  current = second;
  const token2 = await mint(second);
  assert.equal((await verifier.verify(token2)).sub, "0xabc");
  assert.equal(fetches, 2);
  assert.equal(await verifier.verify(token1), null);
});

test("createVerifier propagates key loading failures", async () => {
  const failing = {
    async signingKey() {
      throw new Error("unused");
    },
    async publicKeys() {
      throw new Error("openbao unreachable");
    },
  };
  const verifier = createVerifier({ signer: failing, issuer: ISS, audience: AUD });
  await assert.rejects(() => verifier.verify("a.b.c"), /openbao unreachable/);
});
