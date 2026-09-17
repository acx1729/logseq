"use strict";

const crypto = require("node:crypto");
const { formatSiweMessage } = require("./siwe");

const STYLE = `
:root { color-scheme: light dark; --bg: #f7f7f5; --fg: #1c1c1a; --muted: #6b6b66; --card: #ffffff; --line: #e2e2dd; --accent: #2563eb; --danger: #b91c1c; }
@media (prefers-color-scheme: dark) { :root { --bg: #131312; --fg: #ececea; --muted: #a2a29c; --card: #1e1e1c; --line: #33332f; --accent: #60a5fa; --danger: #f87171; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 420px; margin: 8vh auto; padding: 0 16px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 24px; }
h1 { font-size: 20px; margin: 0 0 4px; }
p { margin: 8px 0; color: var(--muted); }
button { display: flex; align-items: center; gap: 12px; width: 100%; margin-top: 10px; padding: 12px 14px; font: inherit; color: var(--fg); background: var(--bg); border: 1px solid var(--line); border-radius: 10px; cursor: pointer; text-align: left; }
button:hover { border-color: var(--accent); }
button:disabled { opacity: 0.6; cursor: default; }
button img { width: 28px; height: 28px; border-radius: 6px; }
.status { margin-top: 16px; font-size: 14px; }
.error { color: var(--danger); }
code { display: block; margin-top: 8px; padding: 10px; background: var(--bg); border: 1px dashed var(--line); border-radius: 8px; word-break: break-all; font-size: 13px; user-select: all; }
a { color: var(--accent); }
.hidden { display: none; }
`;

const SCRIPT = `
(function () {
  var params = JSON.parse(document.getElementById("siwe-params").textContent);
  var formatSiweMessage = ${formatSiweMessage.toString()};
  var wallets = new Map();
  var list = document.getElementById("wallets");
  var status = document.getElementById("status");
  var result = document.getElementById("result");
  var busy = false;

  function setStatus(text, isError) {
    status.textContent = text;
    status.className = isError ? "status error" : "status";
  }

  function utf8ToHex(text) {
    var bytes = new TextEncoder().encode(text);
    var hex = "0x";
    for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, "0");
    return hex;
  }

  function render() {
    list.textContent = "";
    if (wallets.size === 0) {
      setStatus("No wallet extension found in this browser. Install MetaMask, Rabby or another EIP-6963 wallet and reload.", true);
      return;
    }
    setStatus("Choose the wallet to sign in with.", false);
    wallets.forEach(function (entry) {
      var button = document.createElement("button");
      button.type = "button";
      if (entry.info.icon) {
        var icon = document.createElement("img");
        icon.src = entry.info.icon;
        icon.alt = "";
        button.appendChild(icon);
      }
      var label = document.createElement("span");
      label.textContent = "Continue with " + entry.info.name;
      button.appendChild(label);
      button.addEventListener("click", function () { signIn(entry.provider); });
      list.appendChild(button);
    });
  }

  async function signIn(provider) {
    if (busy) return;
    busy = true;
    try {
      setStatus("Waiting for your wallet\\u2026", false);
      var accounts = await provider.request({ method: "eth_requestAccounts" });
      var address = accounts && accounts[0];
      if (!address) throw new Error("The wallet did not return an account.");
      var chainHex = await provider.request({ method: "eth_chainId" });
      var chainId = parseInt(chainHex, 16);
      var nonceResponse = await fetch("/auth/nonce", { method: "GET", headers: { accept: "application/json" } });
      if (!nonceResponse.ok) throw new Error("The server did not issue a nonce (" + nonceResponse.status + ").");
      var nonce = (await nonceResponse.json()).nonce;
      var issuedAt = new Date();
      var message = formatSiweMessage({
        domain: location.host,
        address: address,
        statement: params.statement,
        uri: location.origin + location.pathname,
        chainId: chainId,
        nonce: nonce,
        issuedAt: issuedAt.toISOString(),
        expirationTime: new Date(issuedAt.getTime() + 5 * 60 * 1000).toISOString()
      });
      var signature = await provider.request({ method: "personal_sign", params: [utf8ToHex(message), address] });
      var response = await fetch("/auth/siwe", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          message: message,
          signature: signature,
          code_challenge: params.code_challenge,
          code_challenge_method: "S256",
          redirect_uri: params.redirect_uri
        })
      });
      var body = await response.json();
      if (!response.ok) throw new Error(body && body.error ? body.error : "Sign-in was refused (" + response.status + ").");
      var target = new URL(params.redirect_uri);
      target.searchParams.set("code", body.code);
      target.searchParams.set("state", params.state);
      document.getElementById("code").textContent = body.code;
      document.getElementById("return-link").href = target.toString();
      result.className = "";
      list.className = "hidden";
      setStatus("Signed in. Returning to " + params.app_name + "\\u2026", false);
      location.assign(target.toString());
    } catch (error) {
      setStatus(error && error.message ? error.message : String(error), true);
    } finally {
      busy = false;
    }
  }

  window.addEventListener("eip6963:announceProvider", function (event) {
    var detail = event.detail;
    if (detail && detail.info && detail.provider) {
      wallets.set(detail.info.rdns || detail.info.name, detail);
      render();
    }
  });
  window.dispatchEvent(new Event("eip6963:requestProvider"));
  setTimeout(function () {
    if (wallets.size === 0 && window.ethereum) {
      wallets.set("window.ethereum", { info: { name: "your browser wallet", icon: null }, provider: window.ethereum });
    }
    render();
  }, 400);
})();
`;

function sha256Base64(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("base64");
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function jsonForScriptTag(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}

/**
 * Hosted sign-in page for the authorization-code flow (desktop and CLI).
 * All parameters are validated by the caller before rendering. Returns the
 * HTML and the response headers, including a hash-based Content Security
 * Policy for the inline script and style.
 */
function renderSignInPage({ appName, statement, state, codeChallenge, redirectUri }) {
  const params = jsonForScriptTag({
    app_name: appName,
    statement,
    state,
    code_challenge: codeChallenge,
    redirect_uri: redirectUri,
  });
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Sign in to ${escapeHtml(appName)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
  <div class="card">
    <h1>Sign in to ${escapeHtml(appName)}</h1>
    <p>Your wallet address is your account. Signing costs nothing and sends no transaction.</p>
    <div id="wallets"></div>
    <div id="status" class="status"></div>
    <div id="result" class="hidden">
      <p>If ${escapeHtml(appName)} did not open, <a id="return-link" href="#">return to the app</a> or paste this code into it:</p>
      <code id="code"></code>
    </div>
  </div>
</main>
<script type="application/json" id="siwe-params">${params}</script>
<script>${SCRIPT}</script>
</body>
</html>
`;
  const csp = [
    "default-src 'none'",
    `script-src 'sha256-${sha256Base64(SCRIPT)}'`,
    `style-src 'sha256-${sha256Base64(STYLE)}'`,
    "connect-src 'self'",
    "img-src data: https:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
  return {
    html,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": csp,
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  };
}

module.exports = { renderSignInPage, SCRIPT, STYLE };
