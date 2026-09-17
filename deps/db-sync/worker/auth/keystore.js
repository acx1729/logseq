"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

/**
 * Graph keys: one random AES-256 key per graph, generated when the graph is
 * created and handed to members over the authenticated key route. The key
 * never enters the index database. Production keeps it in an OpenBao KV v2
 * mount; development and CI keep it as a file under the data directory.
 */
const KEY_BYTES = 32;
const GRAPH_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9._/-]+$/;

class KeyExistsError extends Error {
  constructor(graphId) {
    super(`graph key already exists: ${graphId}`);
    this.name = "KeyExistsError";
  }
}

function assertGraphId(graphId) {
  if (typeof graphId !== "string" || !GRAPH_ID_PATTERN.test(graphId)) {
    throw new Error("graph id must be letters, digits, '.', '_' or '-'");
  }
}

function generateKey() {
  return crypto.randomBytes(KEY_BYTES);
}

function decodeKey(encoded, graphId) {
  const key = typeof encoded === "string" ? Buffer.from(encoded, "base64") : null;
  if (!key || key.length !== KEY_BYTES) {
    throw new Error(`stored key for graph ${graphId} is not ${KEY_BYTES} bytes`);
  }
  return key;
}

/** Keys as files under `dir`, one per graph, for development and CI. */
function fileKeyStore({ dir }) {
  if (typeof dir !== "string" || dir === "") {
    throw new Error("key store directory is required");
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyPath = (graphId) => {
    assertGraphId(graphId);
    return path.join(dir, `${graphId}.key`);
  };
  return {
    kind: "file",
    async createKey(graphId) {
      const file = keyPath(graphId);
      const key = generateKey();
      try {
        fs.writeFileSync(file, key.toString("base64"), { flag: "wx", mode: 0o600 });
      } catch (error) {
        if (error.code === "EEXIST") throw new KeyExistsError(graphId);
        throw error;
      }
      return key;
    },
    async getKey(graphId) {
      const file = keyPath(graphId);
      let encoded;
      try {
        encoded = fs.readFileSync(file, "utf8");
      } catch (error) {
        if (error.code === "ENOENT") return null;
        throw error;
      }
      return decodeKey(encoded.trim(), graphId);
    },
    async deleteKey(graphId) {
      fs.rmSync(keyPath(graphId), { force: true });
    },
  };
}

function cleanSegment(value, label) {
  if (typeof value !== "string" || value === "" || !PATH_SEGMENT_PATTERN.test(value)) {
    throw new Error(`openbao ${label} must be a path of letters, digits, '.', '_', '-' or '/'`);
  }
  const trimmed = value.replace(/^\/+|\/+$/g, "");
  if (trimmed === "") {
    throw new Error(`openbao ${label} must not be empty`);
  }
  return trimmed;
}

/**
 * Keys in an OpenBao KV v2 mount, one secret per graph under `prefix`. Writes
 * use check-and-set version 0 so a key is never overwritten; deletes remove
 * the secret's metadata and every version with it.
 */
function openBaoKeyStore({ client, mount = "logseq", prefix = "graphs" }) {
  if (!client || typeof client.request !== "function") {
    throw new Error("openbao key store needs an OpenBao client");
  }
  const mountPath = cleanSegment(mount, "kv mount");
  const prefixPath = cleanSegment(prefix, "kv prefix");
  const dataPath = (graphId) => {
    assertGraphId(graphId);
    return `/v1/${mountPath}/data/${prefixPath}/${graphId}`;
  };
  const metadataPath = (graphId) => {
    assertGraphId(graphId);
    return `/v1/${mountPath}/metadata/${prefixPath}/${graphId}`;
  };
  return {
    kind: "openbao",
    async createKey(graphId) {
      const key = generateKey();
      try {
        await client.request("POST", dataPath(graphId), {
          data: { key: key.toString("base64") },
          options: { cas: 0 },
        });
      } catch (error) {
        if (error.status === 400) throw new KeyExistsError(graphId);
        throw error;
      }
      return key;
    },
    async getKey(graphId) {
      const body = await client.request("GET", dataPath(graphId), undefined, { allowNotFound: true });
      const data = body && body.data && body.data.data;
      if (!data) return null;
      return decodeKey(data.key, graphId);
    },
    async deleteKey(graphId) {
      await client.request("DELETE", metadataPath(graphId), undefined, { allowNotFound: true });
    },
  };
}

/**
 * Build a key store from the adapter configuration:
 * `{kind: "file", dir}` or `{kind: "openbao", client, mount, prefix}`.
 */
function createKeyStore(options) {
  const kind = options && options.kind;
  if (kind === "file") {
    return fileKeyStore({ dir: options.dir });
  }
  if (kind === "openbao") {
    return openBaoKeyStore({ client: options.client, mount: options.mount, prefix: options.prefix });
  }
  throw new Error(`unsupported key store: ${kind}`);
}

module.exports = { KEY_BYTES, KeyExistsError, createKeyStore, fileKeyStore, openBaoKeyStore };
