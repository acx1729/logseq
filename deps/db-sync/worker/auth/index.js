"use strict";

/**
 * Wallet sign-in for the Logseq sync server: Sign-In with Ethereum (EIP-4361)
 * verified with viem, RS256 tokens signed by OpenBao Transit or a PEM key, an
 * authorization-code flow with PKCE for desktop and CLI, and the hosted
 * sign-in page. Loaded by the ClojureScript adapter at runtime.
 */
const { AuthError } = require("./errors");
const jwt = require("./jwt");
const page = require("./page");
const pkce = require("./pkce");
const { createRateLimiter } = require("./ratelimit");
const { createAuthService, parseBody, SCOPE } = require("./service");
const signers = require("./signers");
const siwe = require("./siwe");
const { AUTH_MIGRATIONS, createAuthStore } = require("./store");

module.exports = {
  AUTH_MIGRATIONS,
  AuthError,
  SCOPE,
  createAuthService,
  createAuthStore,
  createRateLimiter,
  createSigner: signers.createSigner,
  fileSigner: signers.fileSigner,
  transitSigner: signers.transitSigner,
  createVerifier: jwt.createVerifier,
  decodeToken: jwt.decodeToken,
  mintToken: jwt.mintToken,
  verifyToken: jwt.verifyToken,
  parseBody,
  pkce,
  renderSignInPage: page.renderSignInPage,
  siwe,
};
