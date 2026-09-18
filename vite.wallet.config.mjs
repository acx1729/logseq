// Builds the wallet bundle: RainbowKit, wagmi and viem with their own React
// root, loaded by the app on demand from ./js/wallet.js (see
// src/main/frontend/wallet.cljs). It is built apart from the ClojureScript
// build because the web3 libraries ship as ES modules with dynamic imports
// that shadow-cljs does not bundle.
import { resolve } from "node:path";
import { defineConfig } from "vite";

const outDir = process.env.WALLET_OUT_DIR || "static/js";

export default defineConfig({
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
  },
  build: {
    outDir,
    emptyOutDir: false,
    sourcemap: false,
    minify: true,
    target: "es2020",
    lib: {
      entry: resolve(process.cwd(), "src/wallet/index.js"),
      name: "logseqWallet",
      formats: ["iife"],
      fileName: () => "wallet.js",
      cssFileName: "wallet",
    },
  },
});
