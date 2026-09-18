// Sign-in with the identity this device holds, used by the login screen and
// by the app's silent renewal before a token expires.
import { WalletError } from "./errors.js";
import { accountOf } from "./identity.js";
import { fetchServerConfig } from "./server.js";
import { signIn } from "./siwe.js";

/**
 * identityStore: { read(): Promise<identity|null>, write(identity), remove() }
 * where identity is { phrase, address, displayName? }.
 */
export async function signInWithIdentity({ serverUrl, serverConfig, platform, identityStore, username, fetch }) {
  const identity = await identityStore.read();
  if (!identity) {
    throw new WalletError("no_identity", "this device holds no identity");
  }
  const config = serverConfig || (await fetchServerConfig(serverUrl, fetch ? { fetch } : {}));
  const account = accountOf(identity);
  const result = await signIn({
    serverConfig: config,
    platform,
    address: account.address,
    chainId: config.chainIds[0],
    signMessage: (message) => account.signMessage({ message }),
    username: username ?? identity.displayName,
    fetch,
  });
  if (username && username !== identity.displayName) {
    await identityStore.write({ ...identity, displayName: username });
  }
  return result;
}
