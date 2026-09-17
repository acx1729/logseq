"use strict";

const crypto = require("node:crypto");
const b64 = require("./base64url");

const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;

function sha256(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest();
}

function challengeForVerifier(verifier) {
  return b64.encode(sha256(verifier));
}

function validChallenge(challenge) {
  return typeof challenge === "string" && CHALLENGE_RE.test(challenge);
}

function verifierMatches(verifier, challenge) {
  if (typeof verifier !== "string" || !VERIFIER_RE.test(verifier) || !validChallenge(challenge)) {
    return false;
  }
  const expected = Buffer.from(challengeForVerifier(verifier));
  const actual = Buffer.from(challenge);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function randomCode() {
  return b64.encode(crypto.randomBytes(32));
}

function hashCode(code) {
  return sha256(code).toString("hex");
}

/** 32 hexadecimal characters: alphanumeric and long enough for EIP-4361. */
function randomNonce() {
  return crypto.randomBytes(16).toString("hex");
}

module.exports = { challengeForVerifier, validChallenge, verifierMatches, randomCode, hashCode, randomNonce };
