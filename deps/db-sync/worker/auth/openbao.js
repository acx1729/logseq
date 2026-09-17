"use strict";

const fs = require("node:fs");

/**
 * Reads a secret from its value or, when the value is empty, from a file.
 * Used for the AppRole secret id so it can be mounted instead of exported.
 */
function readSecret(value, file, label) {
  if (typeof value === "string" && value !== "") return value;
  if (typeof file === "string" && file !== "") return fs.readFileSync(file, "utf8").trim();
  throw new Error(`${label} is required`);
}

/**
 * One OpenBao session for the whole server; the Transit signer and the graph
 * key store share it. Authenticates with a static token (development) or
 * AppRole (production), re-authenticates once when OpenBao answers 403, and
 * turns every other failure into an error carrying the HTTP status. A 404
 * resolves to null only when the caller passes `allowNotFound`; a 204 and an
 * empty body resolve to null.
 */
function createOpenBaoClient({
  baseUrl,
  token = null,
  roleId = null,
  secretId = null,
  secretIdFile = null,
  fetch = globalThis.fetch,
  now = Date.now,
}) {
  if (typeof baseUrl !== "string" || !/^https?:\/\//.test(baseUrl)) {
    throw new Error("openbao address must be an http(s) URL");
  }
  const staticToken = typeof token === "string" && token !== "" ? token : null;
  const approleId = staticToken ? null : roleId;
  const approleSecret = staticToken ? null : readSecret(secretId, secretIdFile, "openbao secret id");
  if (!staticToken && !approleId) {
    throw new Error("openbao auth requires a token or an AppRole role id and secret id");
  }
  const root = baseUrl.replace(/\/+$/, "");
  let clientToken = null;
  let tokenExpiresAt = 0;

  async function login() {
    if (staticToken) {
      clientToken = staticToken;
      tokenExpiresAt = Number.POSITIVE_INFINITY;
      return;
    }
    const response = await fetch(`${root}/v1/auth/approle/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ role_id: approleId, secret_id: approleSecret }),
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

  async function request(method, path, body, options = {}, retryOnForbidden = true) {
    if (!clientToken || now() >= tokenExpiresAt) {
      await login();
    }
    const response = await fetch(`${root}${path}`, {
      method,
      headers: { "X-Vault-Token": clientToken, "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 403 && retryOnForbidden && !staticToken) {
      clientToken = null;
      return request(method, path, body, options, false);
    }
    if (response.status === 404 && options.allowNotFound) {
      return null;
    }
    if (!response.ok) {
      const error = new Error(`openbao ${method} ${path} failed: ${response.status}`);
      error.status = response.status;
      throw error;
    }
    if (response.status === 204) {
      return null;
    }
    const text = await response.text();
    return text === "" ? null : JSON.parse(text);
  }

  return { request };
}

module.exports = { createOpenBaoClient, readSecret };
