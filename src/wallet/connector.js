// A wagmi connector over the identity this device holds: an EIP-1193
// provider that answers account and signing requests from the local key and
// forwards read-only calls to the chain's RPC endpoint, so ENS lookups and
// chain switching work as they do for any wallet.
import { ChainNotConfiguredError, createConnector } from "@wagmi/core";
import { createClient, getAddress, http, isHex, numberToHex, SwitchChainError } from "viem";
import { WalletError } from "./errors.js";
import { accountOf } from "./identity.js";

export const IDENTITY_CONNECTOR_ID = "logseq-identity";

export function logseqIdentityConnector({ identityStore, name, icon }) {
  return createConnector((config) => {
    let chainId = config.chains[0].id;
    let identity = null;

    async function loadIdentity() {
      identity = await identityStore.read();
      return identity;
    }

    function currentAccount(address) {
      if (!identity) {
        throw new WalletError("no_identity", "this device holds no identity");
      }
      if (address !== undefined && getAddress(address) !== getAddress(identity.address)) {
        throw new WalletError("unknown_account", `${address} is not this device's identity`);
      }
      return accountOf(identity);
    }

    function chainClient() {
      const chain = config.chains.find((candidate) => candidate.id === chainId);
      const transport = config.transports && config.transports[chainId];
      return createClient({ chain, transport: transport || http() });
    }

    const provider = {
      async request({ method, params }) {
        switch (method) {
          case "eth_chainId":
            return numberToHex(chainId);
          case "eth_accounts":
          case "eth_requestAccounts": {
            const current = identity || (await loadIdentity());
            return current ? [getAddress(current.address)] : [];
          }
          case "personal_sign": {
            const [data, address] = params;
            const account = currentAccount(address);
            return account.signMessage({ message: isHex(data) ? { raw: data } : data });
          }
          case "eth_signTypedData_v4": {
            const [address, json] = params;
            const account = currentAccount(address);
            return account.signTypedData(typeof json === "string" ? JSON.parse(json) : json);
          }
          case "wallet_switchEthereumChain": {
            const target = Number(params[0].chainId);
            if (!config.chains.some((candidate) => candidate.id === target)) {
              throw new SwitchChainError(new ChainNotConfiguredError());
            }
            chainId = target;
            config.emitter.emit("change", { chainId });
            return null;
          }
          case "wallet_addEthereumChain":
            return null;
          default:
            return chainClient().request({ method, params });
        }
      },
    };

    return {
      id: IDENTITY_CONNECTOR_ID,
      name,
      type: IDENTITY_CONNECTOR_ID,
      icon,
      async setup() {
        await loadIdentity();
      },
      async connect({ chainId: requested } = {}) {
        const current = await loadIdentity();
        if (!current) {
          throw new WalletError("no_identity", "this device holds no identity");
        }
        if (requested !== undefined) {
          if (!config.chains.some((candidate) => candidate.id === requested)) {
            throw new SwitchChainError(new ChainNotConfiguredError());
          }
          chainId = requested;
        }
        return { accounts: [getAddress(current.address)], chainId };
      },
      async disconnect() {},
      async getAccounts() {
        const current = identity || (await loadIdentity());
        return current ? [getAddress(current.address)] : [];
      },
      async getChainId() {
        return chainId;
      },
      async getProvider() {
        return provider;
      },
      async isAuthorized() {
        return Boolean(identity || (await loadIdentity()));
      },
      async switchChain({ chainId: target }) {
        const chain = config.chains.find((candidate) => candidate.id === target);
        if (!chain) throw new SwitchChainError(new ChainNotConfiguredError());
        chainId = target;
        config.emitter.emit("change", { chainId: target });
        return chain;
      },
      onAccountsChanged(accounts) {
        if (accounts.length === 0) this.onDisconnect();
        else config.emitter.emit("change", { accounts: accounts.map((address) => getAddress(address)) });
      },
      onChainChanged(chain) {
        chainId = Number(chain);
        config.emitter.emit("change", { chainId });
      },
      onDisconnect() {
        config.emitter.emit("disconnect");
      },
      /** Re-reads the identity store after the app created or removed an identity. */
      async refreshIdentity() {
        const before = identity ? getAddress(identity.address) : null;
        const current = await loadIdentity();
        const after = current ? getAddress(current.address) : null;
        if (before && !after) this.onDisconnect();
        else if (after && before !== after) this.onAccountsChanged([after]);
      },
    };
  });
}
