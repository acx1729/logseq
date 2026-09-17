"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const b64 = require("./base64url");

const MIN_MODULUS_BITS = 2048;

/** RFC 7638 JWK thumbprint for an RSA public key. */
function rsaThumbprint(jwk) {
  const canonical = JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n });
  return b64.encode(crypto.createHash("sha256").update(canonical).digest());
}

function publicJwk(keyObject, kid) {
  const exported = keyObject.export({ format: "jwk" });
  return { kty: "RSA", n: exported.n, e: exported.e, kid, alg: "RS256", use: "sig" };
}

function assertRsaKey(keyObject, label) {
  if (keyObject.asymmetricKeyType !== "rsa") {
    throw new Error(`${label} must be an RSA key`);
  }
  const bits = keyObject.asymmetricKeyDetails && keyObject.asymmetricKeyDetails.modulusLength;
  if (typeof bits !== "number" || bits < MIN_MODULUS_BITS) {
    throw new Error(`${label} must be at least ${MIN_MODULUS_BITS} bits`);
  }
}

/**
 * Signs with a PEM private key held in memory. Meant for development and CI;
 * production deployments sign through OpenBao Transit so the private key never
 * exists on the sync server.
 */
function fileSigner({ privateKeyPem }) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  assertRsaKey(privateKey, "token signing key");
  const publicKey = crypto.createPublicKey(privateKey);
  const kid = rsaThumbprint(publicKey.export({ format: "jwk" }));
  const jwk = publicJwk(publicKey, kid);
  return {
    kind: "file",
    async signingKey() {
      return {
        kid,
        sign: async (data) => crypto.sign("RSA-SHA256", data, privateKey),
      };
    },
    async publicKeys() {
      return [jwk];
    },
  };
}

function parseTransitSignature(value) {
  const match = /^vault:v(\d+):(.+)$/.exec(typeof value === "string" ? value : "");
  if (!match) {
    throw new Error("openbao returned an unexpected signature format");
  }
  return { version: Number(match[1]), signature: Buffer.from(match[2], "base64") };
}

/**
 * Signs through an OpenBao Transit key. Authenticates with a static token
 * (development) or AppRole (production) and re-authenticates on 403 or when
 * the lease is near its end. Public keys come from the key's versions and are
 * exposed as JWKs with `kid` = `v<version>`.
 */
function transitSigner({
  baseUrl,
  mount = "transit",
  keyName,
  token = null,
  roleId = null,
  secretId = null,
  fetch = globalThis.fetch,
  now = Date.now,
  keyCacheMs = 5 * 60 * 1000,
}) {
  if (typeof baseUrl !== "string" || !/^https?:\/\//.test(baseUrl)) {
    throw new Error("openbao address must be an http(s) URL");
  }
  if (typeof keyName !== "string" || keyName === "") {
    throw new Error("openbao transit key name is required");
  }
  if (!token && !(roleId && secretId)) {
    throw new Error("openbao auth requires a token or an AppRole role id and secret id");
  }
  const root = baseUrl.replace(/\/+$/, "");
  let clientToken = null;
  let tokenExpiresAt = 0;
  let keyInfo = null;

  async function login() {
    if (token) {
      clientToken = token;
      tokenExpiresAt = Number.POSITIVE_INFINITY;
      return;
    }
    const response = await fetch(`${root}/v1/auth/approle/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
    });
    if (!response.ok) {
      throw new Error(`openbao approle login failed: ${response.status}`);
    }
    const body = await response.json();
    const auth = body && body.auth;
    if (!auth || typeof auth.client_token !== "string") {
      throw new Error("openbao approle login returned no client token");
    }
    clientToken = auth.client_token;
    const leaseS = typeof auth.lease_duration === "number" && auth.lease_duration > 0 ? auth.lease_duration : 3600;
    tokenExpiresAt = now() + Math.floor(leaseS * 0.8) * 1000;
  }

  async function request(method, path, body, retryOnForbidden = true) {
    if (!clientToken || now() >= tokenExpiresAt) {
      await login();
    }
    const response = await fetch(`${root}${path}`, {
      method,
      headers: { "X-Vault-Token": clientToken, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 403 && retryOnForbidden && !token) {
      clientToken = null;
      return request(method, path, body, false);
    }
    if (!response.ok) {
      throw new Error(`openbao ${method} ${path} failed: ${response.status}`);
    }
    return response.json();
  }

  async function readKey(force) {
    if (!force && keyInfo && now() - keyInfo.fetchedAt < keyCacheMs) {
      return keyInfo;
    }
    const body = await request("GET", `/v1/${mount}/keys/${encodeURIComponent(keyName)}`);
    const data = body && body.data;
    if (!data || typeof data.type !== "string" || !data.type.startsWith("rsa")) {
      throw new Error("openbao transit key must be an RSA key");
    }
    const latestVersion = Number(data.latest_version);
    const minVersion = Number(data.min_decryption_version || 1);
    const keys = [];
    for (const [versionText, entry] of Object.entries(data.keys || {})) {
      const version = Number(versionText);
      if (!Number.isInteger(version) || version < minVersion) continue;
      if (!entry || typeof entry.public_key !== "string") continue;
      const keyObject = crypto.createPublicKey(entry.public_key);
      assertRsaKey(keyObject, `openbao transit key version ${version}`);
      keys.push(publicJwk(keyObject, `v${version}`));
    }
    if (!Number.isInteger(latestVersion) || !keys.some((jwk) => jwk.kid === `v${latestVersion}`)) {
      throw new Error("openbao transit key has no usable latest version");
    }
    keyInfo = { latestVersion, keys, fetchedAt: now() };
    return keyInfo;
  }

  async function signingKey() {
    const { latestVersion } = await readKey(false);
    return {
      kid: `v${latestVersion}`,
      sign: async (data) => {
        const body = await request("POST", `/v1/${mount}/sign/${encodeURIComponent(keyName)}`, {
          input: Buffer.from(data).toString("base64"),
          key_version: latestVersion,
          hash_algorithm: "sha2-256",
          signature_algorithm: "pkcs1v15",
        });
        const { version, signature } = parseTransitSignature(body && body.data && body.data.signature);
        if (version !== latestVersion) {
          throw new Error("openbao signed with an unexpected key version");
        }
        return signature;
      },
    };
  }

  async function publicKeys(force) {
    return (await readKey(force)).keys;
  }

  return { kind: "transit", signingKey, publicKeys };
}

function readSecret(value, file, label) {
  if (typeof value === "string" && value !== "") return value;
  if (typeof file === "string" && file !== "") return fs.readFileSync(file, "utf8").trim();
  throw new Error(`${label} is required`);
}

/**
 * Build a signer from the adapter configuration.
 * `{kind: "file", keyFile}` or
 * `{kind: "transit", baseUrl, mount, keyName, token, roleId, secretId, secretIdFile}`.
 */
function createSigner(options) {
  const kind = options && options.kind;
  if (kind === "file") {
    if (typeof options.keyFile !== "string" || options.keyFile === "") {
      throw new Error("token signing key file is required for the file signer");
    }
    return fileSigner({ privateKeyPem: fs.readFileSync(options.keyFile, "utf8") });
  }
  if (kind === "transit") {
    const token = typeof options.token === "string" && options.token !== "" ? options.token : null;
    return transitSigner({
      baseUrl: options.baseUrl,
      mount: options.mount || "transit",
      keyName: options.keyName,
      token,
      roleId: token ? null : options.roleId,
      secretId: token ? null : readSecret(options.secretId, options.secretIdFile, "openbao secret id"),
      fetch: options.fetch,
    });
  }
  throw new Error(`unsupported token signer: ${kind}`);
}

module.exports = { fileSigner, transitSigner, createSigner, rsaThumbprint, parseTransitSignature };
