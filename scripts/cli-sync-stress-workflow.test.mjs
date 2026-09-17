import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflowPath = new URL("../.github/workflows/cli-sync-stress.yml", import.meta.url);
const nodeAdapterPath = new URL("../deps/db-sync/worker/dist/node-adapter.js", import.meta.url);

test("CLI sync stress workflow runs local sync/offline stress and validates the graph", () => {
  const workflow = readFileSync(workflowPath, "utf8");

  assert.match(workflow, /^name: CLI sync stress$/m);
  assert.match(workflow, /pnpm --dir deps\/db-sync build:node-adapter/);
  assert.match(workflow, /opam exec -- pnpm cli:release/);
  assert.match(workflow, /pnpm db-worker-node:release:bundle/);
  assert.match(workflow, /node deps\/db-sync\/scripts\/generate-signing-key\.mjs tmp\/cli-sync-stress\/signing-key\.pem/);
  assert.match(workflow, /node deps\/db-sync\/scripts\/mint-token\.mjs/);
  assert.match(workflow, /--issuer http:\/\/127\.0\.0\.1:18080/);
  assert.match(workflow, /--write-auth tmp\/cli-sync-stress\/home\/logseq\/auth\.json/);
  assert.match(workflow, /DB_SYNC_TOKEN_SIGNING_KEY_FILE: \$\{\{ github\.workspace \}\}\/tmp\/cli-sync-stress\/signing-key\.pem/);
  assert.doesNotMatch(workflow, /COGNITO|jwks\.json|http\.createServer/);
  assert.match(workflow, /LOGSEQ_CLI_ROOT_DIR/);
  assert.match(workflow, /HOME: \$\{\{ github\.workspace \}\}\/tmp\/cli-sync-stress\/home/);
  assert.match(workflow, /node scripts\/cli-concurrent-edit-stress\.mjs/);
  assert.match(workflow, /--sync/);
  assert.match(workflow, /--offline/);
  assert.match(workflow, /graph validate --graph "\$GRAPH" --output json/);
});

test("db-sync node adapter does not require Sentry during startup", () => {
  const adapter = readFileSync(nodeAdapterPath, "utf8");

  assert.doesNotMatch(adapter, /SHADOW_IMPORT\("shadow\.js\.shim\.module\$\$sentry\$node\.js"\)/);
});
