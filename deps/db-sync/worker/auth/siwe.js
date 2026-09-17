"use strict";

const { getAddress, recoverMessageAddress } = require("viem");
const { createSiweMessage, parseSiweMessage, validateSiweMessage } = require("viem/siwe");
const { AuthError } = require("./errors");

const ISSUED_AT_FUTURE_SKEW_MS = 5 * 60 * 1000;

/**
 * EIP-4361 text for the fields the hosted sign-in page fills in. Kept free of
 * dependencies because its source is inlined into that page; the output is
 * byte-identical to viem's `createSiweMessage` for the same fields.
 */
function formatSiweMessage(fields) {
  var origin = fields.scheme ? fields.scheme + "://" + fields.domain : fields.domain;
  var statement = fields.statement ? fields.statement + "\n" : "";
  var text = origin + " wants you to sign in with your Ethereum account:\n" + fields.address + "\n\n" + statement +
    "\nURI: " + fields.uri + "\nVersion: 1\nChain ID: " + fields.chainId + "\nNonce: " + fields.nonce +
    "\nIssued At: " + fields.issuedAt;
  if (fields.expirationTime) text += "\nExpiration Time: " + fields.expirationTime;
  return text;
}

function shortAddress(address) {
  const checksummed = getAddress(address);
  return `${checksummed.slice(0, 6)}…${checksummed.slice(-4)}`;
}

/**
 * Verify a signed EIP-4361 message. `domains` is a Set of allowed lowercase
 * authorities, `chainIds` a Set of allowed EIP-155 ids or null for any chain.
 * Resolves to the parsed identity; throws AuthError when the sign-in must be
 * refused. The nonce is returned for the caller to consume exactly once.
 */
async function verifySiweSignIn({ message, signature, domains, chainIds = null, nowMs = Date.now() }) {
  if (typeof message !== "string" || message === "" || typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new AuthError("invalid_request", "message and signature are required", 400);
  }
  const parsed = parseSiweMessage(message);
  if (!parsed.address || !parsed.domain || !parsed.nonce || !parsed.uri || parsed.version !== "1" ||
      !Number.isInteger(parsed.chainId) || !(parsed.issuedAt instanceof Date) || Number.isNaN(parsed.issuedAt.getTime())) {
    throw new AuthError("invalid_siwe_message", "message is not a valid Sign-In with Ethereum message", 400);
  }
  if (!domains.has(parsed.domain.toLowerCase())) {
    throw new AuthError("siwe_domain_not_allowed", "message domain is not served by this server", 400);
  }
  if (chainIds && !chainIds.has(parsed.chainId)) {
    throw new AuthError("siwe_chain_not_allowed", "message chain id is not accepted", 400);
  }
  if (!validateSiweMessage({ message: parsed, time: new Date(nowMs) })) {
    throw new AuthError("siwe_message_expired", "message is expired, not yet valid or malformed", 400);
  }
  if (parsed.issuedAt.getTime() > nowMs + ISSUED_AT_FUTURE_SKEW_MS) {
    throw new AuthError("siwe_issued_in_future", "message issued-at is in the future", 400);
  }
  let recovered;
  try {
    recovered = await recoverMessageAddress({ message, signature });
  } catch {
    throw new AuthError("invalid_signature", "signature could not be verified", 401);
  }
  if (recovered.toLowerCase() !== parsed.address.toLowerCase()) {
    throw new AuthError("invalid_signature", "signature does not match the message address", 401);
  }
  const address = parsed.address.toLowerCase();
  return {
    address,
    checksumAddress: getAddress(address),
    chainId: parsed.chainId,
    nonce: parsed.nonce,
    domain: parsed.domain,
    uri: parsed.uri,
  };
}

module.exports = { createSiweMessage, formatSiweMessage, parseSiweMessage, shortAddress, verifySiweSignIn };
