#!/usr/bin/env bash
set -euo pipefail

# Local development defaults: a signing key on disk, graph keys as files under
# the data directory and the web app's dev origin as the SIWE domain.
# Production sets every variable explicitly and keeps both in OpenBao
# (DB_SYNC_TOKEN_SIGNER=transit, DB_SYNC_KEY_STORE=openbao; see README.md).
: "${DB_SYNC_PORT:=8787}"
: "${DB_SYNC_DATA_DIR:=data/db-sync}"
: "${DB_SYNC_TOKEN_ISSUER:=http://127.0.0.1:${DB_SYNC_PORT}}"
: "${DB_SYNC_TOKEN_SIGNER:=file}"
: "${DB_SYNC_TOKEN_SIGNING_KEY_FILE:=${DB_SYNC_DATA_DIR}/signing-key.pem}"
: "${DB_SYNC_KEY_STORE:=file}"
: "${DB_SYNC_SIWE_DOMAINS:=localhost:3001,127.0.0.1:3001,localhost:${DB_SYNC_PORT},127.0.0.1:${DB_SYNC_PORT}}"

export DB_SYNC_PORT DB_SYNC_DATA_DIR DB_SYNC_TOKEN_ISSUER DB_SYNC_TOKEN_SIGNER \
  DB_SYNC_TOKEN_SIGNING_KEY_FILE DB_SYNC_KEY_STORE DB_SYNC_SIWE_DOMAINS

if [ "$DB_SYNC_TOKEN_SIGNER" = "file" ]; then
  node scripts/generate-signing-key.mjs "$DB_SYNC_TOKEN_SIGNING_KEY_FILE"
fi

node worker/dist/node-adapter.js
