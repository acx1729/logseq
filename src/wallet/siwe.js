// Sign-In with Ethereum messages as every Logseq client builds them.
import { createSiweMessage, parseSiweMessage } from "viem/siwe";
import { fetchNonce, postSignIn } from "./server.js";

export const MESSAGE_LIFETIME_MS = 5 * 60 * 1000;

/**
 * The authority a client names in its message: a browser names its own
 * origin (the operator lists it in DB_SYNC_SIWE_DOMAINS), while the desktop
 * and mobile shells name the sync server itself.
 */
export function siweDomain(platform, serverConfig) {
  if (platform === "web") {
    const host = globalThis.location && globalThis.location.host;
    if (typeof host === "string" && host !== "") return host;
  }
  return serverConfig.issuerHost;
}

export function buildSiweMessage({ address, chainId, domain, uri, nonce, statement, now = new Date() }) {
  return createSiweMessage({
    address,
    chainId,
    domain,
    nonce,
    uri,
    version: "1",
    statement,
    issuedAt: now,
    expirationTime: new Date(now.getTime() + MESSAGE_LIFETIME_MS),
  });
}

export function addressOfMessage(message) {
  return parseSiweMessage(message).address;
}

/**
 * One sign-in: nonce, message, signature from `signMessage(text)`, token.
 * Resolves to `{ accessToken, expiresIn, address }`.
 */
export async function signIn({ serverConfig, platform, address, chainId, signMessage, username, fetch }) {
  const options = fetch ? { fetch } : {};
  const nonce = await fetchNonce(serverConfig.serverUrl, options);
  const message = buildSiweMessage({
    address,
    chainId,
    domain: siweDomain(platform, serverConfig),
    uri: serverConfig.issuer,
    nonce,
    statement: serverConfig.statement,
  });
  const signature = await signMessage(message);
  const result = await postSignIn(serverConfig.serverUrl, { message, signature, username }, options);
  return { ...result, address };
}
