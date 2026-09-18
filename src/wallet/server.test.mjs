import assert from "node:assert/strict";
import test from "node:test";
import { fetchNonce, fetchServerConfig, normalizeServerUrl, postSignIn } from "./server.js";

function fakeFetch(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url, init });
    const route = routes[new URL(url).pathname];
    if (!route) return { ok: false, status: 404, text: async () => JSON.stringify({ error: "not_found" }) };
    const { status = 200, body } = typeof route === "function" ? route(init) : route;
    return { ok: status >= 200 && status < 300, status, text: async () => (body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body)) };
  };
  return { fetch, calls };
}

const CONFIG = {
  issuer: "https://sync.example.test",
  app_name: "Hobby Notes",
  statement: "Sign in to Logseq",
  chain_ids: [1, 10],
  rpc_urls: { 1: "https://rpc.example.test" },
  walletconnect_project_id: null,
};

test("normalizeServerUrl accepts http(s) addresses and strips trailing slashes", () => {
  assert.equal(normalizeServerUrl(" https://sync.example.test/// "), "https://sync.example.test");
  assert.equal(normalizeServerUrl("http://127.0.0.1:8787"), "http://127.0.0.1:8787");
  assert.throws(() => normalizeServerUrl("sync.example.test"), (e) => e.code === "invalid_server_url");
  assert.throws(() => normalizeServerUrl(""), (e) => e.code === "invalid_server_url");
});

test("fetchServerConfig validates and reshapes the published configuration", async () => {
  const { fetch, calls } = fakeFetch({ "/auth/config": { body: CONFIG } });
  const config = await fetchServerConfig("https://sync.example.test/", { fetch });
  assert.deepEqual(config, {
    serverUrl: "https://sync.example.test",
    issuer: "https://sync.example.test",
    issuerHost: "sync.example.test",
    appName: "Hobby Notes",
    statement: "Sign in to Logseq",
    chainIds: [1, 10],
    rpcUrls: { 1: "https://rpc.example.test" },
    walletConnectProjectId: null,
  });
  assert.equal(calls[0].url, "https://sync.example.test/auth/config");
  for (const broken of [
    { ...CONFIG, chain_ids: [] },
    { ...CONFIG, chain_ids: ["1"] },
    { ...CONFIG, issuer: "" },
    { ...CONFIG, issuer: "sync.example.test" },
    { ...CONFIG, walletconnect_project_id: "" },
    { ...CONFIG, rpc_urls: null },
  ]) {
    const { fetch: brokenFetch } = fakeFetch({ "/auth/config": { body: broken } });
    await assert.rejects(() => fetchServerConfig("https://sync.example.test", { fetch: brokenFetch }), (e) => e.code === "server_response");
  }
  const { fetch: htmlFetch } = fakeFetch({ "/auth/config": { body: "<html>" } });
  await assert.rejects(() => fetchServerConfig("https://sync.example.test", { fetch: htmlFetch }), (e) => e.code === "server_response");
  const unreachable = async () => {
    throw new Error("ECONNREFUSED");
  };
  await assert.rejects(() => fetchServerConfig("https://sync.example.test", { fetch: unreachable }), (e) => e.code === "server_unreachable");
});

test("fetchNonce and postSignIn carry the server's refusal codes", async () => {
  const { fetch, calls } = fakeFetch({
    "/auth/nonce": { body: { nonce: "0123456789abcdef0123456789abcdef", expires_at: 1 } },
    "/auth/siwe": (init) => {
      const body = JSON.parse(init.body);
      if (body.username === "bad") return { status: 400, body: { error: "invalid_username", error_description: "no" } };
      return { body: { token_type: "Bearer", access_token: "t.o.k", expires_in: 60, scope: "logseq/read logseq/write" } };
    },
  });
  assert.equal(await fetchNonce("https://sync.example.test", { fetch }), "0123456789abcdef0123456789abcdef");
  const issued = await postSignIn("https://sync.example.test", { message: "m", signature: "0x1", username: " Ada " }, { fetch });
  assert.deepEqual(issued, { accessToken: "t.o.k", expiresIn: 60 });
  assert.deepEqual(JSON.parse(calls[1].init.body), { message: "m", signature: "0x1", username: "Ada" });
  await postSignIn("https://sync.example.test", { message: "m", signature: "0x1", username: "   " }, { fetch });
  assert.deepEqual(JSON.parse(calls[2].init.body), { message: "m", signature: "0x1" });
  await assert.rejects(
    () => postSignIn("https://sync.example.test", { message: "m", signature: "0x1", username: "bad" }, { fetch }),
    (e) => e.code === "invalid_username" && e.status === 400 && e.message === "no",
  );
});
