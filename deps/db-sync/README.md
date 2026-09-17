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

Sign in with a throwaway key and write the token where the CLI reads it
(`~/logseq/auth.json` holds `{"access-token": "<token>"}`):

```bash
node scripts/siwe-login.mjs --server http://127.0.0.1:8787 --username "CI runner" --write-auth ~/logseq/auth.json
```

Point the CLI at the server with these `cli.edn` keys:

```clojure
{:http-base "http://127.0.0.1:8787"
 :ws-url "ws://127.0.0.1:8787/sync/%s"}
```

`logseq login` signs in with the identity the CLI holds in
`~/logseq/identity.json`, creating one on first use; no browser is involved
(see `docs/cli/logseq-cli.md`).

## Authentication

Every credential is a token minted by this server after it verified a wallet
signature. Tokens are RS256 JWTs whose `sub` is the lowercase wallet address
and whose `username` is the display name on file; they live
`DB_SYNC_TOKEN_TTL_S` seconds (30 days by default) and are renewed by signing
in again. There are no refresh tokens and no other sign-in path: the web app,
desktop, mobile and CLI all post a signed message here, from a wallet the app
holds or from an external one.

| Route | Purpose |
| --- | --- |
| `GET /auth/config` | What a client needs before signing in: `issuer`, `app_name`, `statement`, `chain_ids`, `rpc_urls`, `walletconnect_project_id` |
| `GET /auth/nonce` | A single-use nonce, valid five minutes |
| `POST /auth/siwe` | Verifies JSON `{message, signature, username?}` and returns `{token_type, access_token, expires_in, scope}` |
| `GET /auth/jwks.json` | The public keys tokens are verified with |

Verification checks the message domain against `DB_SYNC_SIWE_DOMAINS`, the
chain id against `DB_SYNC_SIWE_CHAIN_IDS`, expiry and not-before, recovers
the signer (externally owned accounts only), and consumes the nonce. Browser
clients name their own origin as the message domain; desktop, mobile and CLI
clients name the issuer, so `DB_SYNC_SIWE_DOMAINS` must include the issuer's
host and the server refuses to start otherwise. The `/auth/*` routes are rate
limited per client address; set `DB_SYNC_TRUST_PROXY=true` behind a reverse
proxy so the address comes from `X-Forwarded-For`.

Display names: a sign-in may carry `username` (1 to 64 characters, no control
characters). The name is stored in `users.username` and returned in the
token; a sign-in without one keeps the stored name, and a first sign-in
without one records the short form of the address (`0x1234…abcd`). Members
of a graph see each other's names through `GET /graphs/:graph-id/members`.

Client configuration: `DB_SYNC_SIWE_CHAIN_IDS` lists the chains wallets may
sign on (default `1`, Ethereum mainnet) and the same list is published to
clients, which build their wallet setup from it. `DB_SYNC_RPC_URLS` overrides
the public RPC endpoint a client uses per chain (`1=https://...,10=https://...`),
for ENS lookups and chain switching; without it clients use each chain's
public endpoint. `DB_SYNC_WALLETCONNECT_PROJECT_ID` enables WalletConnect
wallets in the app's wallet picker; without it the app offers its built-in
identity and browser-injected wallets only.

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

## Graph keys

Every graph is encrypted by its members with one AES-256 key. This server
generates the key when the graph is created and hands it to members over
`GET /graphs/:graph-id/key`, which answers `{"key": "<base64>"}` to members
and 403 to everyone else. The key never enters the index database. Two stores
exist:

- `DB_SYNC_KEY_STORE=file`: one file per graph under `DB_SYNC_KEY_STORE_DIR`
  (default `<data dir>/keys`, created with mode 0600), for development and CI.
- `DB_SYNC_KEY_STORE=openbao`: an OpenBao KV v2 mount (`BAO_KV_MOUNT`, default
  `logseq`) with one secret per graph under `BAO_KV_PREFIX` (default `graphs`),
  written with check-and-set version 0 so a key is never overwritten. The
  transit signer and the key store share one OpenBao session and the same
  `BAO_*` credentials. The policy needs `create` and `read` on
  `<mount>/data/<prefix>/*` and `delete` on `<mount>/metadata/<prefix>/*`.

Creating a graph writes the key first and answers 503 with no rows written
when the store is unavailable; deleting a graph removes the key last, after
its rows and storage. Removing a member does not rotate the key.

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
| DB_SYNC_TOKEN_AUDIENCE | The `aud` claim (default `logseq-sync`) |
| DB_SYNC_TOKEN_TTL_S | Token lifetime in seconds (default 2592000) |
| DB_SYNC_TOKEN_SIGNER | Required. `file` or `transit` |
| DB_SYNC_TOKEN_SIGNING_KEY_FILE | PEM private key for the file signer |
| DB_SYNC_KEY_STORE | Required. `file` or `openbao` |
| DB_SYNC_KEY_STORE_DIR | Directory of the file key store (default `<data dir>/keys`) |
| BAO_ADDR | OpenBao address for the transit signer and the KV key store |
| BAO_TRANSIT_MOUNT | Transit mount (default `transit`) |
| BAO_TRANSIT_KEY | Transit key name (default `logseq-token`) |
| BAO_KV_MOUNT | KV v2 mount of the graph keys (default `logseq`) |
| BAO_KV_PREFIX | Path prefix of the graph keys in that mount (default `graphs`) |
| BAO_TOKEN | Static OpenBao token (development only) |
| BAO_ROLE_ID, BAO_SECRET_ID, BAO_SECRET_ID_FILE | AppRole credentials |
| DB_SYNC_SIWE_DOMAINS | Required. Comma-separated authorities (host[:port]) sign-in messages may name; must include the issuer's host |
| DB_SYNC_SIWE_CHAIN_IDS | Comma-separated EIP-155 chain ids to accept and to offer clients (default `1`) |
| DB_SYNC_SIWE_STATEMENT | Statement shown in the sign-in message (default `Sign in to Logseq`) |
| DB_SYNC_APP_NAME | Name shown in the wallet picker and sign-in prompts (default `Logseq`) |
| DB_SYNC_RPC_URLS | Per-chain RPC endpoints for clients, `<chain id>=<url>` comma-separated (default: each chain's public endpoint) |
| DB_SYNC_WALLETCONNECT_PROJECT_ID | WalletConnect Cloud project id; unset hides WalletConnect wallets |
| DB_SYNC_LOG_LEVEL | Log level (default `info`) |

## Schema

The index database is created through versioned migrations recorded in
`schema_migrations`: the base entries in `logseq.db-sync.index/index-migrations`
and the auth tables in `worker/auth/store.js`, applied in id order, so a
migration's numeric prefix is its position. Add a new entry for every schema
change and keep the DDL portable (no `pragma`, `autoincrement`, `json_each` or
`insert or replace`). `0003-drop-key-tables` removed the per-user key exchange
tables of earlier builds; graph keys live in the key store above.
`0004-drop-auth-codes` removed the authorization-code table of the hosted
sign-in page, which no longer exists.

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
- The sign-in flow, token format and client configuration are implemented in `worker/auth/`; the ClojureScript adapter maps them to routes in `src/logseq/db_sync/node/auth.cljs`.
