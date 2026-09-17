"use strict";

/**
 * Server library of the Logseq sync server, loaded by the ClojureScript
 * adapter at runtime: Sign-In with Ethereum (EIP-4361) verified with viem,
 * RS256 tokens signed by OpenBao Transit or a PEM key, the client
 * configuration published to wallets, and the graph key store backed by
 * OpenBao KV or files.
 */
const { AuthError } = require("./errors");
const jwt = require("./jwt");
const keystore = require("./keystore");
const openbao = require("./openbao");
const { createRateLimiter } = require("./ratelimit");
const { createAuthService, normalizeUsername, parseBody, SCOPE, USERNAME_MAX_LENGTH } = require("./service");
const signers = require("./signers");
const siwe = require("./siwe");
const { AUTH_MIGRATIONS, createAuthStore } = require("./store");

module.exports = {
  AUTH_MIGRATIONS,
  AuthError,
  KeyExistsError: keystore.KeyExistsError,
  SCOPE,
  USERNAME_MAX_LENGTH,
  createAuthService,
  createAuthStore,
  createKeyStore: keystore.createKeyStore,
  createOpenBaoClient: openbao.createOpenBaoClient,
  createRateLimiter,
  createSigner: signers.createSigner,
  fileKeyStore: keystore.fileKeyStore,
  fileSigner: signers.fileSigner,
  openBaoKeyStore: keystore.openBaoKeyStore,
  transitSigner: signers.transitSigner,
  createVerifier: jwt.createVerifier,
  decodeToken: jwt.decodeToken,
  mintToken: jwt.mintToken,
  verifyToken: jwt.verifyToken,
  normalizeUsername,
  parseBody,
  siwe,
};
