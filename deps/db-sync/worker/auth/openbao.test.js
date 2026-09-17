"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOpenBaoClient, readSecret } = require("./openbao");
const { jsonResponse } = require("./test_helpers");

/** A fake OpenBao that hands out AppRole tokens and answers a few paths. */
function fakeBao({ leaseDuration = 3600 } = {}) {
  const calls = [];
  let counter = 0;
  const validTokens = new Set();
  return {
    calls,
    validTokens,
    fetch: async (url, init) => {
      const { pathname } = new URL(url);
      const body = init && init.body ? JSON.parse(init.body) : null;
      calls.push({ method: init.method, pathname, body, token: init.headers && init.headers["X-Vault-Token"] });
      if (pathname === "/v1/auth/approle/login") {
        if (!body || body.role_id !== "role" || body.secret_id !== "secret") return jsonResponse(400, { errors: ["bad approle"] });
        counter += 1;
        const token = `hvs.token-${counter}`;
        validTokens.add(token);
        return jsonResponse(200, { auth: { client_token: token, lease_duration: leaseDuration } });
      }
      if (!validTokens.has(init.headers["X-Vault-Token"])) return jsonResponse(403, { errors: ["permission denied"] });
      if (pathname === "/v1/sys/health") return jsonResponse(200, { initialized: true });
      if (pathname === "/v1/empty") {
        return { ok: true, status: 204, async json() { throw new Error("no body"); }, async text() { return ""; } };
      }
      return jsonResponse(404, { errors: [] });
    },
  };
}

test("AppRole login happens once and the token is reused", async () => {
  const backend = fakeBao();
  const client = createOpenBaoClient({ baseUrl: "https://bao.example.test/", roleId: "role", secretId: "secret", fetch: backend.fetch });
  assert.deepEqual(await client.request("GET", "/v1/sys/health"), { initialized: true });
  assert.deepEqual(await client.request("GET", "/v1/sys/health"), { initialized: true });
  const logins = backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login");
  assert.equal(logins.length, 1);
  assert.equal(backend.calls[1].token, "hvs.token-1");
  assert.equal(backend.calls[2].token, "hvs.token-1");
});

test("a 403 triggers one re-login, a second 403 is an error", async () => {
  const backend = fakeBao();
  const client = createOpenBaoClient({ baseUrl: "https://bao.example.test", roleId: "role", secretId: "secret", fetch: backend.fetch });
  await client.request("GET", "/v1/sys/health");
  backend.validTokens.clear();
  await client.request("GET", "/v1/sys/health");
  assert.equal(backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login").length, 2);
  backend.validTokens.clear();
  const failing = fakeBao();
  const stubborn = createOpenBaoClient({
    baseUrl: "https://bao.example.test",
    roleId: "role",
    secretId: "secret",
    fetch: async (url, init) => {
      const response = await failing.fetch(url, init);
      const { pathname } = new URL(url);
      return pathname === "/v1/auth/approle/login" ? response : jsonResponse(403, { errors: ["denied"] });
    },
  });
  await assert.rejects(() => stubborn.request("GET", "/v1/sys/health"), (error) => error.status === 403);
});

test("a lease near its end is renewed before the next request", async () => {
  const backend = fakeBao({ leaseDuration: 100 });
  let clock = 0;
  const client = createOpenBaoClient({ baseUrl: "https://bao.example.test", roleId: "role", secretId: "secret", fetch: backend.fetch, now: () => clock });
  await client.request("GET", "/v1/sys/health");
  clock = 79 * 1000;
  await client.request("GET", "/v1/sys/health");
  clock = 81 * 1000;
  await client.request("GET", "/v1/sys/health");
  assert.equal(backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login").length, 2);
});

test("a static token never logs in and a 403 with it is final", async () => {
  const backend = fakeBao();
  backend.validTokens.add("root");
  const client = createOpenBaoClient({ baseUrl: "https://bao.example.test", token: "root", fetch: backend.fetch });
  await client.request("GET", "/v1/sys/health");
  backend.validTokens.clear();
  await assert.rejects(() => client.request("GET", "/v1/sys/health"), (error) => error.status === 403);
  assert.equal(backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login").length, 0);
});

test("404 is an error unless allowed; 204 and empty bodies resolve to null", async () => {
  const backend = fakeBao();
  backend.validTokens.add("root");
  const client = createOpenBaoClient({ baseUrl: "https://bao.example.test", token: "root", fetch: backend.fetch });
  await assert.rejects(() => client.request("GET", "/v1/nothing"), (error) => error.status === 404);
  assert.equal(await client.request("GET", "/v1/nothing", undefined, { allowNotFound: true }), null);
  assert.equal(await client.request("DELETE", "/v1/empty"), null);
  const deleteCall = backend.calls.find((call) => call.pathname === "/v1/empty");
  assert.equal(deleteCall.method, "DELETE");
  assert.equal(deleteCall.body, null);
});

test("configuration is validated and the secret id can come from a file", () => {
  assert.throws(() => createOpenBaoClient({ baseUrl: "bao.example.test", token: "t" }), /http\(s\) URL/);
  assert.throws(() => createOpenBaoClient({ baseUrl: "https://bao.example.test" }), /secret id is required/);
  assert.throws(() => createOpenBaoClient({ baseUrl: "https://bao.example.test", secretId: "s" }), /token or an AppRole/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "db-sync-bao-"));
  const secretFile = path.join(dir, "secret-id");
  fs.writeFileSync(secretFile, "from-file\n");
  assert.equal(readSecret("", secretFile, "openbao secret id"), "from-file");
  assert.equal(readSecret("inline", secretFile, "openbao secret id"), "inline");
  assert.throws(() => readSecret("", "", "openbao secret id"), /required/);
  const client = createOpenBaoClient({ baseUrl: "https://bao.example.test", roleId: "role", secretIdFile: secretFile, fetch: async () => jsonResponse(400, {}) });
  assert.equal(typeof client.request, "function");
  fs.rmSync(dir, { recursive: true, force: true });
});
