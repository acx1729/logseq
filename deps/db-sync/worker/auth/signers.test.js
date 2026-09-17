"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createSigner, fileSigner, parseTransitSignature, transitSigner } = require("./signers");
const { mintToken, verifyToken } = require("./jwt");
const { generateRsaPem, jsonResponse } = require("./test_helpers");

test("fileSigner exposes one RS256 JWK with a thumbprint kid and signs verifiably", async () => {
  const signer = fileSigner({ privateKeyPem: generateRsaPem() });
  const keys = await signer.publicKeys();
  assert.equal(keys.length, 1);
  assert.deepEqual(Object.keys(keys[0]).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
  assert.match(keys[0].kid, /^[A-Za-z0-9_-]{43}$/);
  const { kid, sign } = await signer.signingKey();
  assert.equal(kid, keys[0].kid);
  const data = Buffer.from("hello");
  const signature = await sign(data);
  const publicKey = crypto.createPublicKey({ key: { kty: "RSA", n: keys[0].n, e: keys[0].e }, format: "jwk" });
  assert.equal(crypto.verify("RSA-SHA256", data, publicKey, signature), true);
});

test("fileSigner refuses non-RSA and short keys", () => {
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ type: "pkcs8", format: "pem" });
  assert.throws(() => fileSigner({ privateKeyPem: ec }), /RSA/);
  assert.throws(() => fileSigner({ privateKeyPem: generateRsaPem(1024) }), /2048/);
});

test("createSigner reads the PEM for the file kind and rejects unknown kinds", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "db-sync-signer-"));
  const keyFile = path.join(dir, "key.pem");
  fs.writeFileSync(keyFile, generateRsaPem());
  const signer = createSigner({ kind: "file", keyFile });
  assert.equal(signer.kind, "file");
  assert.throws(() => createSigner({ kind: "file" }), /key file/);
  assert.throws(() => createSigner({ kind: "vault" }), /unsupported token signer/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("parseTransitSignature splits the vault prefix", () => {
  const { version, signature } = parseTransitSignature(`vault:v3:${Buffer.from("sig").toString("base64")}`);
  assert.equal(version, 3);
  assert.equal(signature.toString(), "sig");
  assert.throws(() => parseTransitSignature("nope"), /signature format/);
});

/** A fake OpenBao Transit backend holding real RSA keys per version. */
function fakeTransit({ versions, latestVersion, leaseDuration = 3600 }) {
  const calls = [];
  let tokenCounter = 0;
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
        tokenCounter += 1;
        const token = `hvs.token-${tokenCounter}`;
        validTokens.add(token);
        return jsonResponse(200, { auth: { client_token: token, lease_duration: leaseDuration } });
      }
      if (!validTokens.has(init.headers["X-Vault-Token"])) return jsonResponse(403, { errors: ["permission denied"] });
      if (pathname === "/v1/transit/keys/logseq-token") {
        const keys = {};
        for (const [version, key] of Object.entries(versions)) {
          keys[version] = { public_key: crypto.createPublicKey(key).export({ type: "spki", format: "pem" }) };
        }
        return jsonResponse(200, { data: { type: "rsa-2048", latest_version: latestVersion, min_decryption_version: 1, keys } });
      }
      if (pathname === "/v1/transit/sign/logseq-token") {
        assert.equal(body.hash_algorithm, "sha2-256");
        assert.equal(body.signature_algorithm, "pkcs1v15");
        const key = versions[body.key_version];
        const signature = crypto.sign("RSA-SHA256", Buffer.from(body.input, "base64"), key).toString("base64");
        return jsonResponse(200, { data: { signature: `vault:v${body.key_version}:${signature}` } });
      }
      return jsonResponse(404, { errors: ["not found"] });
    },
  };
}

test("transitSigner logs in with AppRole, signs with the latest version and publishes JWKs per version", async () => {
  const v1 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  const v2 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  const backend = fakeTransit({ versions: { 1: v1, 2: v2 }, latestVersion: 2 });
  const signer = transitSigner({ baseUrl: "https://bao.example.test/", keyName: "logseq-token", roleId: "role", secretId: "secret", fetch: backend.fetch });
  const keys = await signer.publicKeys();
  assert.deepEqual(keys.map((k) => k.kid), ["v1", "v2"]);
  const iat = Math.floor(Date.now() / 1000);
  const token = await mintToken({ signer, claims: { iss: "i", aud: "a", sub: "s", iat, exp: iat + 60 } });
  const payload = verifyToken(token, { issuer: "i", audience: "a", keys });
  assert.equal(payload.sub, "s");
  const signCall = backend.calls.find((call) => call.pathname === "/v1/transit/sign/logseq-token");
  assert.equal(signCall.body.key_version, 2);
  assert.equal(backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login").length, 1);
});

test("transitSigner re-authenticates once when OpenBao answers 403", async () => {
  const v1 = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  const backend = fakeTransit({ versions: { 1: v1 }, latestVersion: 1 });
  const signer = transitSigner({ baseUrl: "https://bao.example.test", keyName: "logseq-token", roleId: "role", secretId: "secret", fetch: backend.fetch });
  await signer.publicKeys();
  backend.validTokens.clear();
  const { sign } = await signer.signingKey();
  const signature = await sign(Buffer.from("data"));
  assert.ok(signature.length > 0);
  assert.equal(backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login").length, 2);
});

test("transitSigner with a static token never calls approle login and rejects non-RSA keys", async () => {
  const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
  const backend = fakeTransit({ versions: { 1: ec }, latestVersion: 1 });
  backend.validTokens.add("root");
  const signer = transitSigner({ baseUrl: "https://bao.example.test", keyName: "logseq-token", token: "root", fetch: async (url, init) => {
    const { pathname } = new URL(url);
    if (pathname === "/v1/transit/keys/logseq-token") {
      return jsonResponse(200, { data: { type: "ecdsa-p256", latest_version: 1, keys: { 1: { public_key: crypto.createPublicKey(ec).export({ type: "spki", format: "pem" }) } } } });
    }
    return backend.fetch(url, init);
  } });
  await assert.rejects(() => signer.publicKeys(), /RSA/);
  assert.equal(backend.calls.filter((call) => call.pathname === "/v1/auth/approle/login").length, 0);
});

test("transitSigner validates its configuration", () => {
  assert.throws(() => transitSigner({ baseUrl: "bao.example.test", keyName: "k", token: "t" }), /http\(s\) URL/);
  assert.throws(() => transitSigner({ baseUrl: "https://bao.example.test", keyName: "", token: "t" }), /key name/);
  assert.throws(() => transitSigner({ baseUrl: "https://bao.example.test", keyName: "k" }), /token or an AppRole/);
});
