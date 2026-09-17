"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { renderSignInPage, SCRIPT, STYLE } = require("./page");

function hash(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64");
}

test("sign-in page embeds escaped parameters and a hash-based CSP", () => {
  const { html, headers } = renderSignInPage({
    appName: "Hobby <Notes>",
    statement: "Sign in to Logseq",
    state: "abc</script><script>alert(1)</script>",
    codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    redirectUri: "logseq://auth/callback",
  });
  assert.match(html, /<title>Sign in to Hobby &lt;Notes&gt;<\/title>/);
  assert.doesNotMatch(html, /abc<\/script>/);
  assert.match(html, /abc\\u003c\/script>/);
  const params = JSON.parse(/id="siwe-params">(.*?)<\/script>/s.exec(html)[1]);
  assert.equal(params.state, "abc</script><script>alert(1)</script>");
  assert.equal(params.redirect_uri, "logseq://auth/callback");
  assert.equal(params.code_challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  assert.equal(params.app_name, "Hobby <Notes>");
  assert.equal(headers["content-type"], "text/html; charset=utf-8");
  assert.match(headers["content-security-policy"], new RegExp(`script-src 'sha256-${hash(SCRIPT).replace(/\+/g, "\\+")}'`));
  assert.match(headers["content-security-policy"], new RegExp(`style-src 'sha256-${hash(STYLE).replace(/\+/g, "\\+")}'`));
  assert.match(headers["content-security-policy"], /default-src 'none'/);
  assert.match(headers["content-security-policy"], /connect-src 'self'/);
  assert.equal(headers["cache-control"], "no-store");
  assert.ok(html.includes(`<script>${SCRIPT}</script>`));
  assert.ok(html.includes(`<style>${STYLE}</style>`));
});

test("sign-in page script is syntactically valid JavaScript and uses the wallet discovery events", () => {
  assert.doesNotThrow(() => new Function(SCRIPT));
  assert.match(SCRIPT, /eip6963:requestProvider/);
  assert.match(SCRIPT, /eth_requestAccounts/);
  assert.match(SCRIPT, /personal_sign/);
  assert.match(SCRIPT, /\/auth\/nonce/);
  assert.match(SCRIPT, /\/auth\/siwe/);
  assert.match(SCRIPT, /function formatSiweMessage/);
});
