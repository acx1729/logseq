import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";
import { buildSiweMessage, siweDomain, signIn } from "./siwe.js";
import { signInWithIdentity } from "./session.js";
import { identityFromPhrase, accountOf } from "./identity.js";

// The sync server's own auth library verifies what the app signs.
const require = createRequire(new URL("../../deps/db-sync/package.json", import.meta.url));
const Database = require("better-sqlite3");
const { AUTH_MIGRATIONS, createAuthService, createAuthStore, fileSigner } = require("./worker/auth");
const nodeCrypto = require("node:crypto");
const { parseSiweMessage } = require("viem/siwe");

function makeService() {
  const db = new Database(":memory:");
  for (const migration of AUTH_MIGRATIONS) for (const statement of migration.statements) db.exec(statement);
  const { privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  return createAuthService({
    config: { issuer: "http://127.0.0.1:8787", audience: "logseq-sync", tokenTtlS: 3600, siweDomains: ["127.0.0.1:8787", "app.example.test"], siweChainIds: [1], siweStatement: "Sign in to Logseq", appName: "Logseq" },
    signer: fileSigner({ privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) }),
    store: createAuthStore(db),
  });
}

/** fetch against the service the way the adapter routes it. */
function serviceFetch(service) {
  const names = new Map();
  return async (url, init = {}) => {
    const { pathname } = new URL(url);
    const respond = (status, body) => ({ ok: status < 300, status, text: async () => JSON.stringify(body) });
    try {
      if (pathname === "/auth/config") return respond(200, service.clientConfig());
      if (pathname === "/auth/nonce") return respond(200, service.issueNonce({}));
      if (pathname === "/auth/siwe") {
        const identity = await service.verifySignIn({ body: JSON.parse(init.body) });
        if (identity.username) names.set(identity.address, identity.username);
        const issued = await service.issueToken({ sub: identity.address, username: names.get(identity.address) || identity.defaultUsername });
        return respond(200, service.tokenResponse(issued));
      }
      return respond(404, { error: "not_found" });
    } catch (error) {
      return respond(error.status || 500, { error: error.code || "server_error", error_description: error.message });
    }
  };
}

const serverConfig = {
  serverUrl: "http://127.0.0.1:8787",
  issuer: "http://127.0.0.1:8787",
  issuerHost: "127.0.0.1:8787",
  appName: "Logseq",
  statement: "Sign in to Logseq",
  chainIds: [1],
  rpcUrls: {},
  walletConnectProjectId: null,
};

test("siweDomain names the browser origin on the web and the issuer elsewhere", () => {
  const saved = globalThis.location;
  globalThis.location = { host: "app.example.test" };
  try {
    assert.equal(siweDomain("web", serverConfig), "app.example.test");
    assert.equal(siweDomain("electron", serverConfig), "127.0.0.1:8787");
    assert.equal(siweDomain("mobile", serverConfig), "127.0.0.1:8787");
  } finally {
    globalThis.location = saved;
  }
});

test("buildSiweMessage produces a five-minute EIP-4361 message", () => {
  const now = new Date("2026-09-18T12:00:00.000Z");
  const message = buildSiweMessage({ address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", chainId: 1, domain: "127.0.0.1:8787", uri: "http://127.0.0.1:8787", nonce: "0123456789abcdef0123456789abcdef", statement: "Sign in to Logseq", now });
  const parsed = parseSiweMessage(message);
  assert.equal(parsed.domain, "127.0.0.1:8787");
  assert.equal(parsed.uri, "http://127.0.0.1:8787");
  assert.equal(parsed.chainId, 1);
  assert.equal(parsed.statement, "Sign in to Logseq");
  assert.equal(parsed.expirationTime.getTime() - parsed.issuedAt.getTime(), 5 * 60 * 1000);
});

test("signIn and signInWithIdentity obtain tokens the server verifies and keep display names", async () => {
  const service = makeService();
  const fetch = serviceFetch(service);
  const identity = identityFromPhrase("test test test test test test test test test test test junk");
  const account = accountOf(identity);
  const direct = await signIn({ serverConfig, platform: "electron", address: account.address, chainId: 1, signMessage: (message) => account.signMessage({ message }), username: "Ada", fetch });
  const claims = await service.verify(direct.accessToken);
  assert.equal(claims.sub, account.address.toLowerCase());
  assert.equal(claims.username, "Ada");
  assert.equal(direct.address, account.address);

  const writes = [];
  const identityStore = { read: async () => ({ ...identity, displayName: "Ada" }), write: async (value) => writes.push(value), remove: async () => {} };
  const renewed = await signInWithIdentity({ serverUrl: "http://127.0.0.1:8787/", platform: "mobile", identityStore, fetch });
  assert.equal((await service.verify(renewed.accessToken)).username, "Ada");
  assert.deepEqual(writes, []);
  const renamed = await signInWithIdentity({ serverUrl: "http://127.0.0.1:8787", serverConfig, platform: "electron", identityStore, username: "Lovelace", fetch });
  assert.equal((await service.verify(renamed.accessToken)).username, "Lovelace");
  assert.equal(writes[0].displayName, "Lovelace");

  const empty = { read: async () => null, write: async () => {}, remove: async () => {} };
  await assert.rejects(() => signInWithIdentity({ serverUrl: "http://127.0.0.1:8787", serverConfig, platform: "electron", identityStore: empty, fetch }), (e) => e.code === "no_identity");
  const wrongChain = { ...serverConfig, chainIds: [10] };
  await assert.rejects(
    () => signIn({ serverConfig: wrongChain, platform: "electron", address: account.address, chainId: 10, signMessage: (message) => account.signMessage({ message }), fetch }),
    (e) => e.code === "siwe_chain_not_allowed",
  );
});
