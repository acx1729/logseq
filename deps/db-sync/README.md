# Logseq DB Sync (deps/db-sync)

The self-hosted sync server for DB graphs: a Node.js process that stores each
graph as a SQLite file, serves the sync HTTP and WebSocket protocol, and signs
users in with a wallet signature (Sign-In with Ethereum, EIP-4361). It is the
only backend of this fork; there is no hosted service and no identity provider.

## Requirements
- Node.js (see repo root for required version) and pnpm
- Clojure (for shadow-cljs builds)
- For production: an OpenBao server with a Transit key for token signing

## Build

```bash
cd deps/db-sync
pnpm install
pnpm build:node-adapter
```

## Run locally

`start.sh` applies development defaults: a signing key file generated under
`data/db-sync/`, the server's own address as token issuer, and the web app's
dev origin (`localhost:3001`) in the allowed sign-in domains.

```bash
cd deps/db-sync
./start.sh
```

Sign in without a browser wallet (a throwaway key is generated) and write the
token where the CLI reads it:

```bash
node scripts/siwe-login.mjs --server http://127.0.0.1:8787 --write-auth ~/logseq/auth.json
```

Point the CLI at the server with these `cli.edn` keys:

```clojure
{:http-base "http://127.0.0.1:8787"
 :ws-url "ws://127.0.0.1:8787/sync/%s"
 :oauth-authorize-endpoint "http://127.0.0.1:8787/auth/siwe/start"
 :oauth-token-endpoint "http://127.0.0.1:8787/auth/token"
 :oauth-client-id "logseq-sync"}
```

`logseq login` then opens the hosted sign-in page in a browser, the wallet
signs, and the page returns to the CLI's loopback callback.

## Authentication

Every credential is a token minted by this server after it verified a wallet
signature. Tokens are RS256 JWTs whose `sub` is the lowercase wallet address;
they live `DB_SYNC_TOKEN_TTL_S` seconds (30 days by default) and are renewed
by signing in again. There are no refresh tokens.

| Route | Purpose |
| --- | --- |
| `GET /auth/nonce` | A single-use nonce, valid five minutes |
| `POST /auth/siwe` | Verifies `{message, signature}`; returns a token, or a one-time code when `code_challenge`, `code_challenge_method=S256` and an allow-listed `redirect_uri` are supplied |
| `GET /auth/siwe/start` | Hosted sign-in page for the authorization-code flow (desktop and CLI): discovers EIP-6963 wallets, signs, and redirects to `redirect_uri` with `code` and `state` |
| `POST /auth/token` | Exchanges `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier` (JSON or form-encoded) for a token |
| `GET /auth/jwks.json` | The public keys tokens are verified with |

Verification checks the message domain against `DB_SYNC_SIWE_DOMAINS`, the
chain id against `DB_SYNC_SIWE_CHAIN_IDS` when set, expiry and not-before,
recovers the signer (externally owned accounts only), and consumes the nonce.
The `/auth/*` routes are rate limited per client address; set
`DB_SYNC_TRUST_PROXY=true` behind a reverse proxy so the address comes from
`X-Forwarded-For`.

Two signers exist:

- `DB_SYNC_TOKEN_SIGNER=file`: an RSA private key in PEM form on disk, for
  development and CI. `scripts/generate-signing-key.mjs <path>` creates one.
- `DB_SYNC_TOKEN_SIGNER=transit`: an OpenBao Transit RSA key. The server signs
  with `POST /v1/<mount>/sign/<key>` (`pkcs1v15`, `sha2-256`) and publishes the
  key's public versions as JWKs, so the private key never exists on the sync
  server. Authenticate with an AppRole (`BAO_ROLE_ID` plus `BAO_SECRET_ID` or
  `BAO_SECRET_ID_FILE`) or, for development, a static `BAO_TOKEN`. The policy
  needs `update` on `<mount>/sign/<key>` and `read` on `<mount>/keys/<key>`.
  Give Node the OpenBao CA through `NODE_EXTRA_CA_CERTS` when it is private.

Authorization is unchanged: the graph owner and the rows in `graph_members`
decide who may read and write a graph. Removing a member closes that member's
open sockets on the graph and drops cached access decisions immediately.

## Environment variables

| Variable | Purpose |
| --- | --- |
| DB_SYNC_PORT | HTTP server port (default 8080) |
| DB_SYNC_BASE_URL | External base URL for asset links |
| DB_SYNC_DATA_DIR | Data directory for the index database, graphs and assets |
| DB_SYNC_STORAGE_DRIVER | Storage backend selection (sqlite) |
| DB_SYNC_ASSETS_DRIVER | Assets backend selection (filesystem) |
| DB_SYNC_ADMIN_TOKEN | Admin-only token for operator graph deletion endpoints |
| DB_SYNC_TRUST_PROXY | `true` to take the client address from `X-Forwarded-For` |
| DB_SYNC_TOKEN_ISSUER | Required. The `iss` claim, an http(s) URL of this server |
| DB_SYNC_TOKEN_AUDIENCE | The `aud` claim and OAuth client id (default `logseq-sync`) |
| DB_SYNC_TOKEN_TTL_S | Token lifetime in seconds (default 2592000) |
| DB_SYNC_TOKEN_SIGNER | Required. `file` or `transit` |
| DB_SYNC_TOKEN_SIGNING_KEY_FILE | PEM private key for the file signer |
| BAO_ADDR | OpenBao address for the transit signer |
| BAO_TRANSIT_MOUNT | Transit mount (default `transit`) |
| BAO_TRANSIT_KEY | Transit key name (default `logseq-token`) |
| BAO_TOKEN | Static OpenBao token (development only) |
| BAO_ROLE_ID, BAO_SECRET_ID, BAO_SECRET_ID_FILE | AppRole credentials |
| DB_SYNC_SIWE_DOMAINS | Required. Comma-separated authorities (host[:port]) sign-in messages may name |
| DB_SYNC_SIWE_CHAIN_IDS | Comma-separated EIP-155 chain ids to accept (default: any) |
| DB_SYNC_SIWE_REDIRECT_URIS | Allowed callbacks for the code flow (default: the desktop deep link and the CLI loopback) |
| DB_SYNC_SIWE_STATEMENT | Statement shown in the sign-in message |
| DB_SYNC_APP_NAME | Name shown on the hosted sign-in page |
| DB_SYNC_LOG_LEVEL | Log level (default `info`) |

## Schema

The index database is created through versioned migrations recorded in
`schema_migrations`: the base entries in `logseq.db-sync.index/index-migrations`
and the auth tables in `worker/auth/store.js`. Add a new entry for every schema
change and keep the DDL portable (no `pragma`, `autoincrement`, `json_each` or
`insert or replace`).

## Tests

```bash
cd deps/db-sync
pnpm test:auth                 # auth library (node --test)
node --test 'scripts/*.test.mjs'
pnpm test:node-adapter         # ClojureScript unit and adapter tests
```

Show stored and recomputed checksum for a local sqlite graph db:

```bash
cd deps/db-sync
pnpm run show-sqlite-checksum -- --db ~/Downloads/test.sqlite
```

## Notes
- Runtime and db-sync engineering guidance is consolidated in `../../docs/agent-guide/implemented/architecture/2026-08-24-logseq-runtime-and-engineering-guide.md`; current protocol and route definitions live under `src/logseq/db_sync/worker/`.
- The sign-in flow, token format and hosted page are implemented in `worker/auth/`; the ClojureScript adapter maps them to routes in `src/logseq/db_sync/node/auth.cljs`.
