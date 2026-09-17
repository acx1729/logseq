# cli-e2e

Shell-first end-to-end tests for logseq CLI.

## Test cli-e2e itself
- Run internal cli-e2e harness unit tests: `bb unit-test`

## cleanup first
- Execute cleanup: terminate stale db-worker-node processes, terminate stale db-sync listeners on port `18080`, and remove cli-e2e temp roots: `bb cleanup`
- Preview cleanup actions only (no kill/delete): `bb cleanup --dry-run`

## Run non-sync suite
- List declared non-sync case ids: `bb list-cases`
- Run non-sync cases with build preflight unless `--skip-build` is provided: `bb test`
  - `bb test --help` for options
  - Increase case-level parallelism with `--jobs N` (default: `4`), for example: `bb test --skip-build --jobs 4`
  - Parallelism is case-scoped only; each case still runs setup/main/cleanup sequentially in the existing ephemeral shell model

## Run sync suite
- List declared sync case ids: `bb list-sync-cases`
- Run sync cases with build preflight by default: `bb test-sync`
  - Add `--skip-build` only when you intentionally want to reuse existing artifacts
  - `bb test-sync --help` for options
  - Increase case-level parallelism with `--jobs N` (default: `4`), for example: `bb test-sync --jobs 4`
  - Parallelism is case-scoped only; each sync case still runs its own setup/main/cleanup sequentially
  - The local db-sync server is shared per suite and starts once before cases begin, then stops once after all cases complete
  - Each sync case gets its own isolated temp root, data directories, home directory, auth copy, and generated config files
  - Configure sync E2EE password: `--e2ee-password <value>` (default: `11111`)
  - Run only sync MVP case: `bb test-sync --case sync-upload-download-mvp`

### Sync suite prerequisites
- No login is needed: the suite starts one shared local db-sync server with a
  throwaway signing key, signs in with a throwaway wallet through
  `deps/db-sync/scripts/siwe-login.mjs`, and copies the minted auth file into
  each case's home directory.
- Sync suite starts/stops one shared local db-sync server per suite run.
- Required build artifact and dependencies for the local db-sync server:
  - `deps/db-sync/worker/dist/node-adapter.js`
  - `deps/db-sync/node_modules` (`pnpm --dir deps/db-sync install --frozen-lockfile`)
- If the artifact is missing, build it before running the sync suite:
  - `pnpm --dir deps/db-sync build:node-adapter`

