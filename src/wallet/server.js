// The sync server's sign-in routes, as the app calls them.
import { WalletError } from "./errors.js";

export function normalizeServerUrl(url) {
  const trimmed = String(url ?? "").trim().replace(/\/+$/, "");
  if (!/^https?:\/\/[^/\s]+/.test(trimmed)) {
    throw new WalletError("invalid_server_url", "the sync server address must be an http(s) URL");
  }
  return trimmed;
}

async function requestJson(url, init, step, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, init);
  } catch (error) {
    throw new WalletError("server_unreachable", `${step}: ${error.message}`, { step });
  }
  const text = await response.text();
  let body = null;
  if (text !== "") {
    try {
      body = JSON.parse(text);
    } catch {
      throw new WalletError("server_response", `${step} returned a non-JSON body (${response.status})`, {
        step,
        status: response.status,
      });
    }
  }
  if (!response.ok) {
    const code = body && typeof body.error === "string" ? body.error : "server_error";
    const description = body && typeof body.error_description === "string" ? body.error_description : `${step} failed (${response.status})`;
    throw new WalletError(code, description, { step, status: response.status });
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new WalletError("server_response", `${step} returned no JSON object`, { step, status: response.status });
  }
  return body;
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

/** What `/auth/config` publishes, validated and in camel case. */
export async function fetchServerConfig(serverUrl, { fetch: fetchImpl = globalThis.fetch } = {}) {
  const base = normalizeServerUrl(serverUrl);
  const body = await requestJson(`${base}/auth/config`, { headers: { accept: "application/json" } }, "GET /auth/config", fetchImpl);
  const chainIds = Array.isArray(body.chain_ids) ? body.chain_ids : [];
  if (!nonEmptyString(body.issuer) || !nonEmptyString(body.app_name) || !nonEmptyString(body.statement) ||
      chainIds.length === 0 || !chainIds.every((id) => Number.isInteger(id) && id > 0) ||
      body.rpc_urls === null || typeof body.rpc_urls !== "object" ||
      !(body.walletconnect_project_id === null || nonEmptyString(body.walletconnect_project_id))) {
    throw new WalletError("server_response", "GET /auth/config returned an incomplete configuration");
  }
  let issuerHost;
  try {
    issuerHost = new URL(body.issuer).host;
  } catch {
    throw new WalletError("server_response", `GET /auth/config issuer is not a URL: ${body.issuer}`);
  }
  return {
    serverUrl: base,
    issuer: body.issuer,
    issuerHost,
    appName: body.app_name,
    statement: body.statement,
    chainIds,
    rpcUrls: Object.fromEntries(Object.entries(body.rpc_urls).filter(([, url]) => nonEmptyString(url))),
    walletConnectProjectId: body.walletconnect_project_id,
  };
}

export async function fetchNonce(serverUrl, { fetch: fetchImpl = globalThis.fetch } = {}) {
  const base = normalizeServerUrl(serverUrl);
  const body = await requestJson(`${base}/auth/nonce`, { headers: { accept: "application/json" } }, "GET /auth/nonce", fetchImpl);
  if (!nonEmptyString(body.nonce)) {
    throw new WalletError("server_response", "GET /auth/nonce returned no nonce");
  }
  return body.nonce;
}

/** Posts a signed message; resolves to `{ accessToken, expiresIn }`. */
export async function postSignIn(serverUrl, { message, signature, username }, { fetch: fetchImpl = globalThis.fetch } = {}) {
  const base = normalizeServerUrl(serverUrl);
  const payload = { message, signature };
  if (nonEmptyString(username)) payload.username = username.trim();
  const body = await requestJson(
    `${base}/auth/siwe`,
    { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(payload) },
    "POST /auth/siwe",
    fetchImpl,
  );
  if (!nonEmptyString(body.access_token) || !Number.isInteger(body.expires_in)) {
    throw new WalletError("server_response", "POST /auth/siwe returned no token");
  }
  return { accessToken: body.access_token, expiresIn: body.expires_in };
}
