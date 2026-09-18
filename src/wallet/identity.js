// The identity the app holds for a person: a BIP-39 recovery phrase and the
// Ethereum address it derives to. The rules match the CLI
// (cli/lib/wallet_identity.ml) so a phrase moves between the two unchanged.
import { generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { mnemonicToAccount } from "viem/accounts";
import { WalletError } from "./errors.js";

export function normalizePhrase(phrase) {
  return String(phrase ?? "")
    .toLowerCase()
    .split(/\s+/)
    .filter((word) => word !== "")
    .join(" ");
}

export function validPhrase(phrase) {
  const normalized = normalizePhrase(phrase);
  return normalized !== "" && validateMnemonic(normalized, wordlist);
}

/** The identity of a phrase: `{ phrase, address }` with a checksummed address. */
export function identityFromPhrase(phrase) {
  const normalized = normalizePhrase(phrase);
  if (!validPhrase(normalized)) {
    throw new WalletError("invalid_phrase", "recovery phrase is not a valid BIP-39 phrase");
  }
  return { phrase: normalized, address: mnemonicToAccount(normalized).address };
}

export function generateIdentity() {
  return identityFromPhrase(generateMnemonic(wordlist));
}

/** The viem local account of an identity, used to sign. */
export function accountOf(identity) {
  return mnemonicToAccount(identity.phrase);
}

export function sameIdentity(left, right) {
  return Boolean(left && right && left.address.toLowerCase() === right.address.toLowerCase());
}

export function shortAddress(address) {
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}
