"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { KEY_BYTES, KeyExistsError, createKeyStore, openBaoKeyStore } = require("./keystore");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "db-sync-keys-"));
}

test("file store creates a 32-byte key once, reads it back and deletes it", async () => {
  const dir = tempDir();
  const store = createKeyStore({ kind: "file", dir: path.join(dir, "keys") });
  assert.equal(store.kind, "file");
  const key = await store.createKey("graph-1");
  assert.equal(key.length, KEY_BYTES);
  assert.deepEqual(await store.getKey("graph-1"), key);
  await assert.rejects(() => store.createKey("graph-1"), KeyExistsError);
  assert.deepEqual(await store.getKey("graph-1"), key);
  assert.equal(await store.getKey("missing"), null);
  const mode = fs.statSync(path.join(dir, "keys", "graph-1.key")).mode & 0o777;
  assert.equal(mode, 0o600);
  await store.deleteKey("graph-1");
  await store.deleteKey("graph-1");
  assert.equal(await store.getKey("graph-1"), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("file store refuses graph ids that could leave the directory", async () => {
  const dir = tempDir();
  const store = createKeyStore({ kind: "file", dir });
  await assert.rejects(() => store.getKey("../escape"), /graph id/);
  await assert.rejects(() => store.createKey("a/b"), /graph id/);
  await assert.rejects(() => store.deleteKey(""), /graph id/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("file store rejects a key file of the wrong size", async () => {
  const dir = tempDir();
  const store = createKeyStore({ kind: "file", dir });
  fs.writeFileSync(path.join(dir, "short.key"), Buffer.alloc(5).toString("base64"));
  await assert.rejects(() => store.getKey("short"), /32 bytes/);
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A fake OpenBao client over a KV v2 mount: `request(method, path, body, options)`. */
function fakeKv() {
  const secrets = new Map();
  const calls = [];
  return {
    secrets,
    calls,
    request: async (method, requestPath, body, options = {}) => {
      calls.push({ method, path: requestPath, body, options });
      const data = /^\/v1\/logseq\/data\/graphs\/([^/]+)$/.exec(requestPath);
      const metadata = /^\/v1\/logseq\/metadata\/graphs\/([^/]+)$/.exec(requestPath);
      if (data && method === "POST") {
        if (body.options.cas === 0 && secrets.has(data[1])) {
          const error = new Error("check-and-set parameter did not match the current version");
          error.status = 400;
          throw error;
        }
        secrets.set(data[1], body.data);
        return { data: { version: 1 } };
      }
      if (data && method === "GET") {
        if (!secrets.has(data[1])) {
          if (options.allowNotFound) return null;
          const error = new Error("not found");
          error.status = 404;
          throw error;
        }
        return { data: { data: secrets.get(data[1]), metadata: { version: 1 } } };
      }
      if (metadata && method === "DELETE") {
        secrets.delete(metadata[1]);
        return null;
      }
      const error = new Error(`unexpected ${method} ${requestPath}`);
      error.status = 404;
      throw error;
    },
  };
}

test("openbao store writes with check-and-set 0, reads and deletes metadata", async () => {
  const kv = fakeKv();
  const store = createKeyStore({ kind: "openbao", client: kv, mount: "logseq", prefix: "graphs" });
  assert.equal(store.kind, "openbao");
  const key = await store.createKey("graph-1");
  assert.equal(key.length, KEY_BYTES);
  assert.deepEqual(kv.calls[0], {
    method: "POST",
    path: "/v1/logseq/data/graphs/graph-1",
    body: { data: { key: key.toString("base64") }, options: { cas: 0 } },
    options: {},
  });
  assert.deepEqual(await store.getKey("graph-1"), key);
  await assert.rejects(() => store.createKey("graph-1"), KeyExistsError);
  assert.equal(await store.getKey("graph-2"), null);
  await store.deleteKey("graph-1");
  assert.deepEqual(kv.calls.at(-1), {
    method: "DELETE",
    path: "/v1/logseq/metadata/graphs/graph-1",
    body: undefined,
    options: { allowNotFound: true },
  });
  assert.equal(await store.getKey("graph-1"), null);
});

test("openbao store treats a soft-deleted version and a bad key as errors or absent", async () => {
  const store = openBaoKeyStore({
    client: {
      request: async (method, requestPath) => {
        if (requestPath.endsWith("/deleted")) return { data: { data: null, metadata: { deletion_time: "2026-01-01T00:00:00Z" } } };
        return { data: { data: { key: "not-32-bytes" }, metadata: {} } };
      },
    },
  });
  assert.equal(await store.getKey("deleted"), null);
  await assert.rejects(() => store.getKey("corrupt"), /32 bytes/);
});

test("openbao store normalizes and validates the mount and prefix", async () => {
  const kv = fakeKv();
  const store = openBaoKeyStore({ client: kv, mount: "/logseq/", prefix: "graphs/" });
  await store.createKey("graph-9");
  assert.equal(kv.calls[0].path, "/v1/logseq/data/graphs/graph-9");
  assert.throws(() => openBaoKeyStore({ client: kv, mount: "" }), /kv mount/);
  assert.throws(() => openBaoKeyStore({ client: kv, prefix: "bad prefix" }), /kv prefix/);
  assert.throws(() => openBaoKeyStore({ client: null }), /OpenBao client/);
  await assert.rejects(() => store.getKey("../graphs"), /graph id/);
});

test("createKeyStore rejects unknown kinds and a missing directory", () => {
  assert.throws(() => createKeyStore({ kind: "vault" }), /unsupported key store/);
  assert.throws(() => createKeyStore({ kind: "file" }), /directory/);
});
