"use strict";

function encode(input) {
  return Buffer.from(input).toString("base64url");
}

function decode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new TypeError("invalid base64url input");
  }
  return Buffer.from(text, "base64url");
}

module.exports = { encode, decode };
