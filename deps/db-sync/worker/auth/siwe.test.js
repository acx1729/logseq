"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");
const { AuthError } = require("./errors");
const { createSiweMessage, randomNonce, shortAddress, verifySiweSignIn } = require("./siwe");

const account = privateKeyToAccount(generatePrivateKey());
const domains = new Set(["sync.example.test", "localhost:8787"]);
const chainIds = new Set([1]);

function baseFields(overrides = {}) {
  const issuedAt = new Date();
  return {
    address: account.address,
    chainId: 1,
    domain: "sync.example.test",
    nonce: "0123456789abcdef0123456789abcdef",
    uri: "https://sync.example.test",
    version: "1",
    statement: "Sign in to Logseq",
    issuedAt,
    expirationTime: new Date(issuedAt.getTime() + 5 * 60 * 1000),
    ...overrides,
  };
}

async function signed(overrides = {}) {
  const message = createSiweMessage(baseFields(overrides));
  const signature = await account.signMessage({ message });
  return { message, signature };
}

test("verifySiweSignIn accepts a valid signed message and lowercases the address", async () => {
  const { message, signature } = await signed();
  const identity = await verifySiweSignIn({ message, signature, domains, chainIds });
  assert.equal(identity.address, account.address.toLowerCase());
  assert.equal(identity.checksumAddress, account.address);
  assert.equal(identity.chainId, 1);
  assert.equal(identity.nonce, "0123456789abcdef0123456789abcdef");
});

test("verifySiweSignIn refuses other domains, chains, expiry, future issuance and tampering", async () => {
  const wrongDomain = await signed({ domain: "evil.example.test" });
  await assert.rejects(() => verifySiweSignIn({ ...wrongDomain, domains, chainIds }), (e) => e instanceof AuthError && e.code === "siwe_domain_not_allowed");
  const wrongChain = await signed({ chainId: 10 });
  await assert.rejects(() => verifySiweSignIn({ ...wrongChain, domains, chainIds }), (e) => e.code === "siwe_chain_not_allowed");
  const otherChain = await verifySiweSignIn({ ...wrongChain, domains, chainIds: new Set([1, 10]) });
  assert.equal(otherChain.chainId, 10);
  const expired = await signed({ expirationTime: new Date(Date.now() - 1000) });
  await assert.rejects(() => verifySiweSignIn({ ...expired, domains, chainIds }), (e) => e.code === "siwe_message_expired");
  const future = await signed({ issuedAt: new Date(Date.now() + 60 * 60 * 1000), expirationTime: new Date(Date.now() + 2 * 60 * 60 * 1000) });
  await assert.rejects(() => verifySiweSignIn({ ...future, domains, chainIds }), (e) => e.code === "siwe_issued_in_future");
  const valid = await signed();
  const tampered = valid.message.replace("Sign in to Logseq", "Send me your keys");
  await assert.rejects(() => verifySiweSignIn({ message: tampered, signature: valid.signature, domains, chainIds }), (e) => e.code === "invalid_signature");
  await assert.rejects(() => verifySiweSignIn({ message: valid.message, signature: "0x1234", domains, chainIds }), (e) => e.code === "invalid_signature");
  await assert.rejects(() => verifySiweSignIn({ message: "hello", signature: valid.signature, domains, chainIds }), (e) => e.code === "invalid_siwe_message");
  await assert.rejects(() => verifySiweSignIn({ message: 42, signature: valid.signature, domains, chainIds }), (e) => e.code === "invalid_request");
});

test("verifySiweSignIn refuses a message signed by a different key", async () => {
  const other = privateKeyToAccount(generatePrivateKey());
  const message = createSiweMessage(baseFields());
  const signature = await other.signMessage({ message });
  await assert.rejects(() => verifySiweSignIn({ message, signature, domains, chainIds }), (e) => e.code === "invalid_signature");
});

test("verifySiweSignIn is a programming error without domain and chain sets", async () => {
  const { message, signature } = await signed();
  await assert.rejects(() => verifySiweSignIn({ message, signature, domains, chainIds: new Set() }), /non-empty domain and chain id sets/);
  await assert.rejects(() => verifySiweSignIn({ message, signature, domains: null, chainIds }), /non-empty domain and chain id sets/);
});

test("randomNonce is 32 hexadecimal characters and never repeats", () => {
  const first = randomNonce();
  assert.match(first, /^[0-9a-f]{32}$/);
  assert.notEqual(first, randomNonce());
});

test("shortAddress shows the checksummed head and tail", () => {
  const short = shortAddress(account.address.toLowerCase());
  assert.equal(short.length, 11);
  assert.equal(short.slice(0, 6), account.address.slice(0, 6));
  assert.equal(short.slice(-4), account.address.slice(-4));
});
