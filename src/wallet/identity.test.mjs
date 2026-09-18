import assert from "node:assert/strict";
import test from "node:test";
import { generateIdentity, identityFromPhrase, normalizePhrase, sameIdentity, shortAddress, validPhrase } from "./identity.js";

const JUNK = "test test test test test test test test test test test junk";
const JUNK_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

test("phrases are normalized, validated and derive the documented address", () => {
  assert.equal(normalizePhrase("  Test\ttest\ntest test test test test test test test test JUNK "), JUNK);
  assert.equal(validPhrase(JUNK), true);
  assert.equal(validPhrase("not a recovery phrase"), false);
  assert.equal(validPhrase(""), false);
  const identity = identityFromPhrase(JUNK.toUpperCase());
  assert.equal(identity.phrase, JUNK);
  assert.equal(identity.address, JUNK_ADDRESS);
  assert.throws(() => identityFromPhrase("abandon abandon"), (e) => e.code === "invalid_phrase");
});

test("generated identities are twelve valid words with a checksummed address", () => {
  const identity = generateIdentity();
  assert.equal(identity.phrase.split(" ").length, 12);
  assert.equal(validPhrase(identity.phrase), true);
  assert.match(identity.address, /^0x[0-9a-fA-F]{40}$/);
  assert.notEqual(identity.address, identity.address.toLowerCase());
  assert.notEqual(generateIdentity().phrase, identity.phrase);
  assert.equal(sameIdentity(identity, { ...identity, address: identity.address.toLowerCase() }), true);
  assert.equal(sameIdentity(identity, identityFromPhrase(JUNK)), false);
  assert.equal(shortAddress(JUNK_ADDRESS), "0xf39F…2266");
});
