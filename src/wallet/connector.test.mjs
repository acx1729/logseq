import assert from "node:assert/strict";
import test from "node:test";
import { verifyMessage } from "viem";
import { mainnet, optimism } from "viem/chains";
import { IDENTITY_CONNECTOR_ID, logseqIdentityConnector } from "./connector.js";
import { identityFromPhrase } from "./identity.js";

const identity = identityFromPhrase("test test test test test test test test test test test junk");

function fakeConfig() {
  const events = [];
  return {
    config: { chains: [mainnet, optimism], emitter: { emit: (name, data) => events.push([name, data]) }, transports: {} },
    events,
  };
}

test("the identity connector answers accounts, chain and signatures from the local key", async () => {
  const { config, events } = fakeConfig();
  let stored = { ...identity, displayName: "Ada" };
  const store = { read: async () => stored, write: async () => {}, remove: async () => {} };
  const connector = logseqIdentityConnector({ identityStore: store, name: "This device", icon: "data:," })(config);
  assert.equal(connector.id, IDENTITY_CONNECTOR_ID);
  await connector.setup();
  assert.equal(await connector.isAuthorized(), true);
  const connected = await connector.connect({ chainId: 10 });
  assert.deepEqual(connected, { accounts: [identity.address], chainId: 10 });
  assert.equal(await connector.getChainId(), 10);
  const provider = await connector.getProvider();
  assert.equal(await provider.request({ method: "eth_chainId" }), "0xa");
  assert.deepEqual(await provider.request({ method: "eth_accounts" }), [identity.address]);
  const signature = await provider.request({ method: "personal_sign", params: ["0x68656c6c6f", identity.address.toLowerCase()] });
  assert.equal(await verifyMessage({ address: identity.address, message: "hello", signature }), true);
  await assert.rejects(
    () => provider.request({ method: "personal_sign", params: ["0x68656c6c6f", "0x0000000000000000000000000000000000000001"] }),
    (e) => e.code === "unknown_account",
  );
  await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: "0x1" }] });
  assert.equal(await connector.getChainId(), 1);
  assert.deepEqual(events.at(-1), ["change", { chainId: 1 }]);
  await assert.rejects(() => connector.switchChain({ chainId: 42 }), /chain/i);
  stored = null;
  await connector.refreshIdentity();
  assert.deepEqual(events.at(-1), ["disconnect", undefined]);
  assert.equal(await connector.isAuthorized(), false);
  await assert.rejects(() => connector.connect(), (e) => e.code === "no_identity");
});
