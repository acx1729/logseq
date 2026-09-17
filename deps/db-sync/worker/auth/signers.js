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
 * Signs through an OpenBao Transit key over the shared OpenBao client. Public
 * keys come from the key's versions and are exposed as JWKs with
 * `kid` = `v<version>`.
 */
function transitSigner({ client, mount = "transit", keyName, now = Date.now, keyCacheMs = 5 * 60 * 1000 }) {
  if (!client || typeof client.request !== "function") {
    throw new Error("openbao transit signer needs an OpenBao client");
  }
  if (typeof keyName !== "string" || keyName === "") {
    throw new Error("openbao transit key name is required");
  }
  let keyInfo = null;

  async function readKey(force) {
    if (!force && keyInfo && now() - keyInfo.fetchedAt < keyCacheMs) {
      return keyInfo;
    }
    const body = await client.request("GET", `/v1/${mount}/keys/${encodeURIComponent(keyName)}`);
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
        const body = await client.request("POST", `/v1/${mount}/sign/${encodeURIComponent(keyName)}`, {
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

/**
 * Build a signer from the adapter configuration.
 * `{kind: "file", keyFile}` or `{kind: "transit", client, mount, keyName}`.
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
    return transitSigner({ client: options.client, mount: options.mount || "transit", keyName: options.keyName });
  }
  throw new Error(`unsupported token signer: ${kind}`);
}

module.exports = { fileSigner, transitSigner, createSigner, rsaThumbprint, parseTransitSignature };
