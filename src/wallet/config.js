// The wagmi configuration built from what the sync server publishes: the
// chains it accepts, the RPC endpoint per chain, and whether WalletConnect
// wallets are offered. The device identity is always the first wallet.
import { connectorsForWallets } from "@rainbow-me/rainbowkit";
import { coinbaseWallet, injectedWallet, metaMaskWallet, rainbowWallet, walletConnectWallet } from "@rainbow-me/rainbowkit/wallets";
import { createConfig, createConnector, http } from "@wagmi/core";
import * as viemChains from "viem/chains";
import { WalletError } from "./errors.js";
import { IDENTITY_CONNECTOR_ID, logseqIdentityConnector } from "./connector.js";

export const IDENTITY_ICON =
  "data:image/svg+xml;utf8," +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><rect width="48" height="48" rx="12" fill="#1f2937"/>' +
      '<circle cx="24" cy="19" r="7" fill="#e5e7eb"/><path d="M11 39c1.5-7 7-11 13-11s11.5 4 13 11z" fill="#e5e7eb"/></svg>',
  );

export function chainById(id) {
  const chain = Object.values(viemChains).find((candidate) => candidate && typeof candidate === "object" && candidate.id === id);
  if (!chain) {
    throw new WalletError("unknown_chain", `chain ${id} is not known to this app`);
  }
  return chain;
}

export function logseqIdentityWallet({ identityStore, name, iconUrl = IDENTITY_ICON }) {
  return () => ({
    id: IDENTITY_CONNECTOR_ID,
    name,
    iconUrl,
    iconBackground: "#1f2937",
    installed: true,
    createConnector: (walletDetails) =>
      createConnector((config) => ({
        ...logseqIdentityConnector({ identityStore, name, icon: iconUrl })(config),
        ...walletDetails,
      })),
  });
}

/**
 * strings: { thisDevice, otherWallets } for the wallet picker's group names.
 * WalletConnect-based wallets appear only when the server carries a project
 * id; browser-injected wallets are discovered through EIP-6963 regardless.
 */
export function createWalletConfig({ serverConfig, identityStore, strings }) {
  const chains = serverConfig.chainIds.map(chainById);
  const transports = Object.fromEntries(chains.map((chain) => [chain.id, http(serverConfig.rpcUrls[String(chain.id)])]));
  const projectId = serverConfig.walletConnectProjectId;
  const others = projectId
    ? [injectedWallet, metaMaskWallet, rainbowWallet, coinbaseWallet, walletConnectWallet]
    : [injectedWallet];
  const connectors = connectorsForWallets(
    [
      { groupName: strings.thisDevice, wallets: [logseqIdentityWallet({ identityStore, name: strings.thisDevice })] },
      { groupName: strings.otherWallets, wallets: others },
    ],
    { appName: serverConfig.appName, projectId: projectId || undefined },
  );
  return createConfig({
    chains,
    transports,
    connectors,
    multiInjectedProviderDiscovery: true,
    ssr: false,
  });
}
