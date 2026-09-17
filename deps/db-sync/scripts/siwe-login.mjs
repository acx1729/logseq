#!/usr/bin/env node
// Signs in to a running sync server with a wallet private key: fetches a
// nonce, signs an EIP-4361 message, posts it to /auth/siwe and prints (or
// writes) the token. Used by the CLI e2e launcher and by developers.
import { mkdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";

const require = createRequire(import.meta.url);
const { generatePrivateKey, privateKeyToAccount } = require("viem/accounts");
const { createSiweMessage } = require("viem/siwe");

export function parseArgs(argv) {
  const opts = { chainId: 1, statement: "Sign in to Logseq" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`missing value for ${arg}`);
      return argv[i];
    };
    switch (arg) {
      case "--server": opts.server = next(); break;
      case "--domain": opts.domain = next(); break;
      case "--private-key": opts.privateKey = next(); break;
      case "--chain-id": opts.chainId = Number(next()); break;
      case "--statement": opts.statement = next(); break;
      case "--write-auth": opts.writeAuth = next(); break;
      default: throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (!opts.server) throw new Error("--server is required");
  return opts;
}

async function readJson(response, label) {
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${label} returned a non-JSON body (${response.status}): ${text.slice(0, 200)}`);
  }
  if (!response.ok) {
    throw new Error(`${label} failed (${response.status}): ${body.error || text}`);
  }
  return body;
}

/** Runs the direct sign-in flow and resolves to `{token, address, expiresIn}`. */
export async function login({ server, domain, privateKey, chainId = 1, statement = "Sign in to Logseq", fetch = globalThis.fetch }) {
  const base = server.replace(/\/+$/, "");
  const account = privateKeyToAccount(privateKey || generatePrivateKey());
  const siweDomain = domain || new URL(base).host;
  const { nonce } = await readJson(await fetch(`${base}/auth/nonce`), "GET /auth/nonce");
  const issuedAt = new Date();
  const message = createSiweMessage({
    address: account.address,
    chainId,
    domain: siweDomain,
    nonce,
    uri: `${base}/auth/siwe/start`,
    version: "1",
    statement,
    issuedAt,
    expirationTime: new Date(issuedAt.getTime() + 5 * 60 * 1000),
  });
  const signature = await account.signMessage({ message });
  const body = await readJson(
    await fetch(`${base}/auth/siwe`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ message, signature }),
    }),
    "POST /auth/siwe",
  );
  return { token: body.access_token, address: account.address.toLowerCase(), expiresIn: body.expires_in };
}

export function authFileJson(token) {
  return `${JSON.stringify({ provider: "siwe", "id-token": token, "access-token": token })}\n`;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const opts = parseArgs(process.argv.slice(2));
  const result = await login(opts);
  if (opts.writeAuth) {
    mkdirSync(dirname(opts.writeAuth), { recursive: true });
    writeFileSync(opts.writeAuth, authFileJson(result.token), { mode: 0o600 });
  }
  console.log(JSON.stringify({ status: "ok", address: result.address, expires_in: result.expiresIn, auth_path: opts.writeAuth || null, token: opts.writeAuth ? undefined : result.token }));
}
