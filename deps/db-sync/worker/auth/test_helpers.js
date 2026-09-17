"use strict";

const crypto = require("node:crypto");
const { fileSigner } = require("./signers");

function generateRsaPem(modulusLength = 2048) {
  const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

function testSigner() {
  return fileSigner({ privateKeyPem: generateRsaPem() });
}

/** Minimal Response-like object for fake fetch implementations. */
function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
    async text() {
      return JSON.stringify(body);
    },
  };
}

module.exports = { generateRsaPem, testSigner, jsonResponse };
