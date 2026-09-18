// Entry of the wallet bundle (see vite.wallet.config.mjs). The app loads it
// on demand and talks to it through `window.logseqWallet`; everything the
// bundle needs from the app (identity storage, translations, platform) comes
// in as options, so the bundle holds no app state of its own.
import "@rainbow-me/rainbowkit/styles.css";
import "./wallet.css";
import { QueryClient } from "@tanstack/react-query";
import { disconnect, getConnections } from "@wagmi/core";
import React from "react";
import { createRoot } from "react-dom/client";
import { createWalletConfig } from "./config.js";
import { WalletError } from "./errors.js";
import { fetchServerConfig, normalizeServerUrl } from "./server.js";
import { signInWithIdentity } from "./session.js";
import { AccountApp, Boot, LoginApp } from "./ui.js";

export { generateIdentity, identityFromPhrase, normalizePhrase, shortAddress, validPhrase } from "./identity.js";
export { fetchServerConfig, normalizeServerUrl } from "./server.js";
export { signIn, buildSiweMessage } from "./siwe.js";
export { signInWithIdentity } from "./session.js";
export { WalletError } from "./errors.js";

let cached = null;

function requireOption(options, name) {
  if (options[name] === undefined || options[name] === null) {
    throw new WalletError("missing_option", `wallet option ${name} is required`);
  }
  return options[name];
}

/**
 * The wagmi configuration for a server, built once per server address and
 * wallet-picker strings so connections persist while the app runs.
 */
async function loadContext({ serverUrl, identityStore, t }) {
  const serverConfig = await fetchServerConfig(serverUrl);
  const strings = { thisDevice: t("wallet/this-device"), otherWallets: t("wallet/other-wallets") };
  const key = JSON.stringify([serverConfig.serverUrl, serverConfig.chainIds, serverConfig.rpcUrls, serverConfig.walletConnectProjectId, strings]);
  if (!cached || cached.key !== key) {
    cached = {
      key,
      wagmiConfig: createWalletConfig({ serverConfig, identityStore, strings }),
      queryClient: new QueryClient(),
    };
  }
  return { serverConfig, wagmiConfig: cached.wagmiConfig, queryClient: cached.queryClient };
}

function mount(element, App, options) {
  const serverUrl = normalizeServerUrl(requireOption(options, "serverUrl"));
  const identityStore = requireOption(options, "identityStore");
  const t = requireOption(options, "t");
  const platform = requireOption(options, "platform");
  const root = createRoot(element);
  root.render(
    React.createElement(Boot, {
      App,
      t,
      loadContext: () => loadContext({ serverUrl, identityStore, t }),
      identityStore,
      platform,
      theme: options.theme === "dark" ? "dark" : "light",
      session: options.session,
      onSignedIn: options.onSignedIn || (() => {}),
      onRenamed: options.onRenamed || (() => {}),
      onIdentityRemoved: options.onIdentityRemoved || (() => {}),
      onError: options.onError || (() => {}),
    }),
  );
  return { unmount: () => root.unmount() };
}

/** Renders the sign-in screen into `element`; resolves tokens through `onSignedIn`. */
export function mountLogin(element, options) {
  return mount(element, LoginApp, options);
}

/** Renders the account screen for a signed-in `session` ({ address, username }). */
export function mountAccount(element, options) {
  if (!options.session || typeof options.session.address !== "string") {
    throw new WalletError("missing_option", "wallet option session.address is required");
  }
  return mount(element, AccountApp, options);
}

/** Signs in again with the identity on this device; used before a token expires. */
export function renewSession({ serverUrl, identityStore, platform, username }) {
  return signInWithIdentity({ serverUrl: normalizeServerUrl(serverUrl), identityStore, platform, username });
}

export async function hasIdentity(identityStore) {
  return Boolean(await identityStore.read());
}

/** Drops every wallet connection; the device identity itself stays. */
export async function signOut() {
  if (!cached) return;
  const connections = getConnections(cached.wagmiConfig);
  for (const connection of connections) {
    await disconnect(cached.wagmiConfig, { connector: connection.connector });
  }
}
