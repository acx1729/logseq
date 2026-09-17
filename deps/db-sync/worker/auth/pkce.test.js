"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const pkce = require("./pkce");

test("PKCE challenge matches its verifier and nothing else", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = pkce.challengeForVerifier(verifier);
  assert.equal(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  assert.equal(pkce.verifierMatches(verifier, challenge), true);
  assert.equal(pkce.verifierMatches(`${verifier}x`, challenge), false);
  assert.equal(pkce.verifierMatches("short", pkce.challengeForVerifier("short")), false);
  assert.equal(pkce.verifierMatches(verifier, "not-a-challenge"), false);
  assert.equal(pkce.validChallenge(challenge), true);
  assert.equal(pkce.validChallenge(`${challenge}=`), false);
});

test("codes and nonces have the expected shape", () => {
  const code = pkce.randomCode();
  assert.match(code, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(code, pkce.randomCode());
  assert.match(pkce.hashCode(code), /^[0-9a-f]{64}$/);
  assert.match(pkce.randomNonce(), /^[0-9a-f]{32}$/);
});
