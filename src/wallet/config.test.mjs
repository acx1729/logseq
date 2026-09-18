import assert from "node:assert/strict";
import test from "node:test";
import { chainById, createWalletConfig } from "./config.js";
import { IDENTITY_CONNECTOR_ID } from "./connector.js";

const store = { read: async () => null, write: async () => {}, remove: async () => {} };
const strings = { thisDevice: "This device", otherWallets: "Other wallets" };

function serverConfig(overrides = {}) {
  return {
    serverUrl: "http://127.0.0.1:8787",
    issuer: "http://127.0.0.1:8787",
    issuerHost: "127.0.0.1:8787",
    appName: "Logseq",
    statement: "Sign in to Logseq",
    chainIds: [1],
    rpcUrls: {},
    walletConnectProjectId: null,
    ...overrides,
  };
}

test("chains come from viem by id", () => {
  assert.equal(chainById(1).name, "Ethereum");
  assert.equal(chainById(10).id, 10);
  assert.throws(() => chainById(123456789), (e) => e.code === "unknown_chain");
});

test("the wallet configuration offers the device identity and injected wallets, WalletConnect only with a project id", () => {
  const plain = createWalletConfig({ serverConfig: serverConfig({ chainIds: [1, 10], rpcUrls: { 1: "https://rpc.example.test" } }), identityStore: store, strings });
  assert.deepEqual(plain.chains.map((chain) => chain.id), [1, 10]);
  const ids = plain.connectors.map((connector) => connector.id);
  assert.equal(ids[0], IDENTITY_CONNECTOR_ID);
  assert.ok(ids.includes("injected"));
  assert.ok(!ids.some((id) => id.includes("walletConnect")));
  // RainbowKit records the wallet it built each connector for in rkDetails.
  const withWalletConnect = createWalletConfig({ serverConfig: serverConfig({ walletConnectProjectId: "wc-project" }), identityStore: store, strings });
  const walletIds = withWalletConnect.connectors.map((connector) => connector.rkDetails.id);
  assert.equal(walletIds[0], IDENTITY_CONNECTOR_ID);
  for (const expected of ["injected", "metaMask", "rainbow", "coinbase", "walletConnect"]) {
    assert.ok(walletIds.includes(expected), `${expected} missing from ${walletIds}`);
  }
});
