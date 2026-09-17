#!/usr/bin/env node
// Mints a sync token offline with the file signer's private key, for CI and
// scripted setups where no wallet signs in. The server started with the same
// DB_SYNC_TOKEN_SIGNING_KEY_FILE, issuer and audience accepts the token.
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname } from "node:path";

const require = createRequire(import.meta.url);
const { fileSigner, mintToken, siwe, SCOPE } = require("../worker/auth");

export function parseArgs(argv) {
  const opts = { ttlS: 3600 };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`missing value for ${arg}`);
      return argv[i];
    };
    switch (arg) {
      case "--key-file": opts.keyFile = next(); break;
      case "--issuer": opts.issuer = next(); break;
      case "--audience": opts.audience = next(); break;
      case "--address": opts.address = next(); break;
      case "--ttl-s": opts.ttlS = Number(next()); break;
      case "--write-auth": opts.writeAuth = next(); break;
      default: throw new Error(`unknown argument: ${arg}`);
    }
  }
  for (const key of ["keyFile", "issuer", "address"]) {
    if (!opts[key]) throw new Error(`--${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)} is required`);
  }
  opts.audience = opts.audience || "logseq-sync";
  return opts;
}

export async function mint({ keyFile, issuer, audience, address, ttlS, now = Date.now }) {
  const signer = fileSigner({ privateKeyPem: readFileSync(keyFile, "utf8") });
  const sub = address.toLowerCase();
  const iat = Math.floor(now() / 1000);
  const claims = { iss: issuer, aud: audience, sub, iat, exp: iat + ttlS, username: siwe.shortAddress(sub), scope: SCOPE };
  return { token: await mintToken({ signer, claims }), claims };
}

export function authFileJson(token) {
  return `${JSON.stringify({ provider: "siwe", "id-token": token, "access-token": token })}\n`;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const opts = parseArgs(process.argv.slice(2));
  const { token, claims } = await mint(opts);
  if (opts.writeAuth) {
    mkdirSync(dirname(opts.writeAuth), { recursive: true });
    writeFileSync(opts.writeAuth, authFileJson(token), { mode: 0o600 });
  }
  console.log(JSON.stringify({ status: "ok", sub: claims.sub, exp: claims.exp, auth_path: opts.writeAuth || null, token: opts.writeAuth ? undefined : token }));
}
