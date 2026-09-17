#!/usr/bin/env node
// Writes an RSA-2048 private key (PKCS#8 PEM) for the file token signer,
// unless the file already exists. Development and CI only: production signs
// through OpenBao Transit.
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export function ensureSigningKey(path) {
  if (existsSync(path)) return false;
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return true;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: generate-signing-key.mjs <path.pem>");
    process.exit(2);
  }
  const created = ensureSigningKey(path);
  console.log(JSON.stringify({ status: "ok", path, created }));
}
