import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ensureSigningKey } from "./generate-signing-key.mjs";
import { authFileJson, mint, parseArgs as parseMintArgs } from "./mint-token.mjs";
import { login, parseArgs as parseLoginArgs } from "./siwe-login.mjs";

const require = createRequire(import.meta.url);
const Database = require("better-sqlite3");
const { AUTH_MIGRATIONS, createAuthService, createAuthStore, fileSigner, parseBody } = require("../worker/auth");

function tmpDir() {
  return mkdtempSync(path.join(os.tmpdir(), "db-sync-scripts-"));
}

/** Minimal HTTP server exposing the auth service the way the adapter does. */
function startAuthServer(service, db) {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const text = Buffer.concat(chunks).toString("utf8");
    try {
      if (url.pathname === "/auth/nonce" && req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(service.issueNonce({ ip: req.socket.remoteAddress })));
        return;
      }
      if (url.pathname === "/auth/siwe" && req.method === "POST") {
        const result = await service.signIn({ ip: req.socket.remoteAddress, body: parseBody(req.headers["content-type"], text) });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(result.kind === "code" ? { code: result.code } : service.tokenResponse(result)));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not found" }));
    } catch (error) {
      res.writeHead(error.status || 500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: error.code || "server_error", error_description: error.message }));
    }
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, db }));
  });
}

function makeService(keyFile, issuer, domain) {
  const db = new Database(":memory:");
  for (const migration of AUTH_MIGRATIONS) for (const statement of migration.statements) db.exec(statement);
  const service = createAuthService({
    config: { issuer, audience: "logseq-sync", tokenTtlS: 3600, siweDomains: [domain], redirectUris: ["logseq://auth/callback"] },
    signer: fileSigner({ privateKeyPem: readFileSync(keyFile, "utf8") }),
    store: createAuthStore(db),
  });
  return { service, db };
}

test("generate-signing-key writes a PEM once", () => {
  const dir = tmpDir();
  const keyFile = path.join(dir, "nested", "key.pem");
  assert.equal(ensureSigningKey(keyFile), true);
  assert.equal(ensureSigningKey(keyFile), false);
  assert.match(readFileSync(keyFile, "utf8"), /BEGIN PRIVATE KEY/);
  rmSync(dir, { recursive: true, force: true });
});

test("mint-token produces a token the same key verifies, with the adapter's claims", async () => {
  const dir = tmpDir();
  const keyFile = path.join(dir, "key.pem");
  ensureSigningKey(keyFile);
  const { service } = makeService(keyFile, "http://127.0.0.1:18080", "127.0.0.1:18080");
  const address = "0x000000000000000000000000000000000000dEaD";
  const { token, claims } = await mint({ keyFile, issuer: "http://127.0.0.1:18080", audience: "logseq-sync", address, ttlS: 60 });
  assert.equal(claims.sub, address.toLowerCase());
  const verified = await service.verify(token);
  assert.equal(verified.sub, address.toLowerCase());
  assert.equal(verified.scope, "logseq/read logseq/write");
  const opts = parseMintArgs(["--key-file", keyFile, "--issuer", "http://x", "--address", address]);
  assert.equal(opts.audience, "logseq-sync");
  assert.throws(() => parseMintArgs(["--key-file", keyFile]), /--issuer is required/);
  assert.deepEqual(JSON.parse(authFileJson("t")), { provider: "siwe", "id-token": "t", "access-token": "t" });
  rmSync(dir, { recursive: true, force: true });
});

test("siwe-login signs in against the auth routes and returns a verifiable token", async () => {
  const dir = tmpDir();
  const keyFile = path.join(dir, "key.pem");
  ensureSigningKey(keyFile);
  const { server, port } = await startAuthServer(...Object.values(makeService(keyFile, "http://127.0.0.1", "127.0.0.1")));
  try {
    const { service } = makeService(keyFile, "http://127.0.0.1", "127.0.0.1");
    const result = await login({ server: `http://127.0.0.1:${port}`, domain: "127.0.0.1" });
    assert.match(result.address, /^0x[0-9a-f]{40}$/);
    const claims = await service.verify(result.token);
    assert.equal(claims.sub, result.address);
    await assert.rejects(() => login({ server: `http://127.0.0.1:${port}`, domain: "evil.example" }), /siwe_domain_not_allowed/);
    const opts = parseLoginArgs(["--server", "http://127.0.0.1:1", "--chain-id", "10"]);
    assert.equal(opts.chainId, 10);
    assert.throws(() => parseLoginArgs([]), /--server is required/);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
