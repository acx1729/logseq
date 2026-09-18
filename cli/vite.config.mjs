import { execFileSync } from "node:child_process";
import { builtinModules } from "node:module";
import { resolve } from "node:path";
import { defineConfig } from "vite";

const entry = resolve(
  process.cwd(),
  "bin/logseq_cli_melange/bin/main.js",
);

const nodeBuiltins = [
  ...builtinModules,
  ...builtinModules.map((moduleName) => `node:${moduleName}`),
];

// Resolved from the published package's dependencies at runtime, never
// bundled: viem carries native-free crypto but is large, and the sign-in
// library must be the same build the sync server verifies with.
const runtimeDependencies = ["@scure/bip39", "viem"];

function isRuntimeDependency(id) {
  return runtimeDependencies.some((name) => id === name || id.startsWith(`${name}/`));
}

const gitCwd = process.env.DUNE_SOURCEROOT ?? process.cwd();

function gitOutput(args) {
  try {
    return execFileSync("git", args, {
      cwd: gitCwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

function gitRevision() {
  // Match Shadow's build-metadata-hook: revision equality governs worker reuse.
  return gitOutput(["describe", "--long", "--always", "--dirty"]) ?? "dev";
}

const buildTime = process.env.LOGSEQ_BUILD_TIME ?? new Date().toISOString();
const revision = process.env.LOGSEQ_REVISION ?? gitRevision();

export default defineConfig({
  define: {
    LOGSEQ_CLI_BUILD_TIME: JSON.stringify(buildTime),
    LOGSEQ_CLI_REVISION: JSON.stringify(revision),
  },
  build: {
    lib: {
      entry,
      formats: ["cjs"],
      fileName: () => "logseq-cli.js",
    },
    emptyOutDir: false,
    minify: true,
    sourcemap: false,
    target: "node22",
    rollupOptions: {
      external: (id) =>
        id.startsWith("node:") || nodeBuiltins.includes(id) || isRuntimeDependency(id),
      output: {
        exports: "auto",
        codeSplitting: false,
      },
    },
    commonjsOptions: {
      include: [
        /\/bin\/logseq_cli_melange\//,
      ],
    },
  },
});
