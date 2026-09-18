// The sign-in and account screens. They run in their own React root inside
// a container the app provides, so the app's React tree never depends on
// wagmi or RainbowKit.
import { QueryClientProvider } from "@tanstack/react-query";
import {
  RainbowKitAuthenticationProvider,
  RainbowKitProvider,
  createAuthenticationAdapter,
  darkTheme,
  lightTheme,
  useConnectModal,
} from "@rainbow-me/rainbowkit";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { WagmiProvider, useAccount, useConnect, useDisconnect, useEnsName } from "wagmi";
import { IDENTITY_CONNECTOR_ID } from "./connector.js";
import { errorMessage } from "./errors.js";
import { generateIdentity, identityFromPhrase, sameIdentity, shortAddress } from "./identity.js";
import { fetchNonce, postSignIn } from "./server.js";
import { signInWithIdentity } from "./session.js";
import { addressOfMessage, buildSiweMessage, siweDomain } from "./siwe.js";

const h = React.createElement;

function Providers({ wagmiConfig, queryClient, theme, adapter, status, children }) {
  return h(
    WagmiProvider,
    { config: wagmiConfig, reconnectOnMount: true },
    h(
      QueryClientProvider,
      { client: queryClient },
      h(
        RainbowKitAuthenticationProvider,
        { adapter, status },
        h(RainbowKitProvider, { theme: theme === "dark" ? darkTheme() : lightTheme(), modalSize: "compact" }, children),
      ),
    ),
  );
}

function Field({ id, label, children }) {
  return h("div", { className: "ls-wallet-field" }, h("label", { htmlFor: id }, label), children);
}

function Button({ action, primary, onClick, disabled, children }) {
  return h(
    "button",
    {
      type: "button",
      className: primary ? "ls-wallet-button ls-wallet-button-primary" : "ls-wallet-button",
      "data-wallet-action": action,
      onClick,
      disabled: Boolean(disabled),
    },
    children,
  );
}

function PhraseWords({ phrase }) {
  return h(
    "ol",
    { className: "ls-wallet-words", "data-wallet-phrase": phrase },
    phrase.split(" ").map((word, index) => h("li", { key: index }, word)),
  );
}

async function copyText(text) {
  if (globalThis.navigator && navigator.clipboard) {
    await navigator.clipboard.writeText(text);
  }
}

/** Sign-in adapter shared by every wallet RainbowKit connects. */
function useSiweAdapter({ serverConfig, platform, usernameRef, onVerified, onError }) {
  return useMemo(
    () =>
      createAuthenticationAdapter({
        getNonce: () => fetchNonce(serverConfig.serverUrl),
        createMessage: ({ nonce, address, chainId }) =>
          buildSiweMessage({
            address,
            chainId,
            domain: siweDomain(platform, serverConfig),
            uri: serverConfig.issuer,
            nonce,
            statement: serverConfig.statement,
          }),
        verify: async ({ message, signature }) => {
          try {
            const result = await postSignIn(serverConfig.serverUrl, {
              message,
              signature,
              username: usernameRef.current,
            });
            onVerified({ ...result, address: addressOfMessage(message), connector: "wallet" });
            return true;
          } catch (error) {
            onError(error);
            throw error;
          }
        },
        signOut: async () => {},
      }),
    [serverConfig, platform, usernameRef, onVerified, onError],
  );
}

function LoginScreen({ serverConfig, identityStore, platform, t, displayName, setDisplayName, finish, onError }) {
  const { openConnectModal } = useConnectModal();
  const account = useAccount();
  const { connectors, connectAsync } = useConnect();
  const { disconnectAsync } = useDisconnect();
  const [identity, setIdentity] = useState(undefined);
  const [mode, setMode] = useState("idle");
  const [draft, setDraft] = useState(null);
  const [saved, setSaved] = useState(false);
  const [phraseText, setPhraseText] = useState("");
  const [error, setError] = useState(null);
  const busy = mode === "busy";

  useEffect(() => {
    let cancelled = false;
    identityStore.read().then(
      (stored) => {
        if (cancelled) return;
        setIdentity(stored);
        if (stored && stored.displayName && !displayName) setDisplayName(stored.displayName);
      },
      (readError) => {
        if (!cancelled) setError(errorMessage(readError));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [identityStore]);

  const fail = useCallback(
    (failure) => {
      setError(errorMessage(failure));
      setMode("idle");
      onError(failure);
    },
    [onError],
  );

  const signInWithDevice = useCallback(
    async (stored) => {
      setError(null);
      setMode("busy");
      try {
        const connector = connectors.find((candidate) => candidate.id === IDENTITY_CONNECTOR_ID);
        if (connector && typeof connector.refreshIdentity === "function") await connector.refreshIdentity();
        if (connector && (!account.isConnected || account.connector?.id !== IDENTITY_CONNECTOR_ID)) {
          await connectAsync({ connector, chainId: serverConfig.chainIds[0] });
        }
        const result = await signInWithIdentity({
          serverUrl: serverConfig.serverUrl,
          serverConfig,
          platform,
          identityStore,
          username: displayName.trim() || undefined,
        });
        finish({ ...result, connector: IDENTITY_CONNECTOR_ID, identity: stored });
      } catch (failure) {
        fail(failure);
      }
    },
    [account.connector, account.isConnected, connectAsync, connectors, displayName, fail, finish, identityStore, platform, serverConfig],
  );

  const startCreate = () => {
    setError(null);
    setDraft(generateIdentity());
    setSaved(false);
    setMode("create");
  };

  const confirmCreate = async () => {
    if (!draft || !saved) return;
    try {
      const created = { ...draft, displayName: displayName.trim() || undefined };
      await identityStore.write(created);
      setIdentity(created);
      await signInWithDevice(created);
    } catch (failure) {
      fail(failure);
    }
  };

  const confirmImport = async () => {
    setError(null);
    let imported;
    try {
      imported = identityFromPhrase(phraseText);
    } catch {
      setError(t("wallet/phrase-invalid"));
      return;
    }
    try {
      if (identity && !sameIdentity(identity, imported)) {
        const connector = connectors.find((candidate) => candidate.id === IDENTITY_CONNECTOR_ID);
        if (account.connector?.id === IDENTITY_CONNECTOR_ID) await disconnectAsync();
        if (connector && typeof connector.refreshIdentity === "function") await connector.refreshIdentity();
      }
      const stored = { ...imported, displayName: displayName.trim() || undefined };
      await identityStore.write(stored);
      setIdentity(stored);
      setPhraseText("");
      await signInWithDevice(stored);
    } catch (failure) {
      fail(failure);
    }
  };

  const chooseWallet = async () => {
    setError(null);
    try {
      if (account.isConnected && account.connector?.id === IDENTITY_CONNECTOR_ID) {
        await disconnectAsync();
      }
      if (openConnectModal) openConnectModal();
    } catch (failure) {
      fail(failure);
    }
  };

  let deviceBody;
  if (identity === undefined) {
    deviceBody = h("p", { className: "ls-wallet-muted" }, t("wallet/loading"));
  } else if (mode === "busy") {
    deviceBody = h("p", { className: "ls-wallet-muted", "data-wallet-state": "busy" }, t("wallet/signing-in"));
  } else if (mode === "create" && draft) {
    deviceBody = h(
      "div",
      { "data-wallet-state": "create" },
      h("p", null, t("wallet/backup-desc")),
      h(PhraseWords, { phrase: draft.phrase }),
      h(
        "div",
        { className: "ls-wallet-row" },
        h(Button, { action: "copy-phrase", onClick: () => copyText(draft.phrase) }, t("wallet/copy-phrase")),
        h(
          "label",
          { className: "ls-wallet-check" },
          h("input", {
            type: "checkbox",
            "data-wallet-action": "confirm-saved",
            checked: saved,
            onChange: (event) => setSaved(event.target.checked),
          }),
          t("wallet/backup-confirm"),
        ),
      ),
      h(
        "div",
        { className: "ls-wallet-row" },
        h(Button, { action: "continue-create", primary: true, disabled: !saved, onClick: confirmCreate }, t("wallet/continue")),
        h(Button, { action: "cancel", onClick: () => setMode("idle") }, t("wallet/cancel")),
      ),
    );
  } else if (mode === "import") {
    deviceBody = h(
      "div",
      { "data-wallet-state": "import" },
      h(
        Field,
        { id: "ls-wallet-phrase", label: t("wallet/recovery-phrase") },
        h("textarea", {
          id: "ls-wallet-phrase",
          rows: 3,
          value: phraseText,
          autoComplete: "off",
          spellCheck: false,
          placeholder: t("wallet/recovery-phrase-placeholder"),
          onChange: (event) => setPhraseText(event.target.value),
        }),
      ),
      h(
        "div",
        { className: "ls-wallet-row" },
        h(Button, { action: "continue-import", primary: true, disabled: phraseText.trim() === "", onClick: confirmImport }, t("wallet/continue")),
        h(Button, { action: "cancel", onClick: () => setMode("idle") }, t("wallet/cancel")),
      ),
    );
  } else if (identity) {
    deviceBody = h(
      "div",
      { "data-wallet-state": "ready" },
      h("div", { className: "ls-wallet-address" }, h("code", { title: identity.address }, shortAddress(identity.address))),
      h(
        "div",
        { className: "ls-wallet-row" },
        h(Button, { action: "sign-in-device", primary: true, onClick: () => signInWithDevice(identity) }, t("wallet/sign-in")),
        h(Button, { action: "use-other-phrase", onClick: () => setMode("import") }, t("wallet/use-another-phrase")),
      ),
    );
  } else {
    deviceBody = h(
      "div",
      { className: "ls-wallet-row", "data-wallet-state": "empty" },
      h(Button, { action: "create-identity", primary: true, onClick: startCreate }, t("wallet/create-identity")),
      h(Button, { action: "import-identity", onClick: () => setMode("import") }, t("wallet/import-identity")),
    );
  }

  return h(
    "div",
    { className: "ls-wallet-login" },
    h(
      Field,
      { id: "ls-wallet-display-name", label: t("wallet/display-name") },
      h("input", {
        id: "ls-wallet-display-name",
        type: "text",
        maxLength: 64,
        value: displayName,
        placeholder: t("wallet/display-name-placeholder"),
        autoComplete: "nickname",
        onChange: (event) => setDisplayName(event.target.value),
      }),
    ),
    h(
      "section",
      { className: "ls-wallet-card" },
      h("h3", null, t("wallet/this-device")),
      h("p", { className: "ls-wallet-muted" }, t("wallet/this-device-desc")),
      deviceBody,
    ),
    h("div", { className: "ls-wallet-divider" }, h("span", null, t("wallet/or"))),
    h(
      "section",
      { className: "ls-wallet-card" },
      h("h3", null, t("wallet/other-wallets")),
      h("p", { className: "ls-wallet-muted" }, t("wallet/other-wallets-desc")),
      h(Button, { action: "choose-wallet", disabled: busy || !openConnectModal, onClick: chooseWallet }, t("wallet/choose-wallet")),
    ),
    error ? h("div", { className: "ls-wallet-error", role: "alert" }, error) : null,
  );
}

export function LoginApp({ context, identityStore, platform, t, theme, onSignedIn, onError }) {
  const { serverConfig, wagmiConfig, queryClient } = context;
  const [status, setStatus] = useState("unauthenticated");
  const [displayName, setDisplayName] = useState("");
  const usernameRef = useRef("");
  usernameRef.current = displayName.trim() || undefined;
  const finish = useCallback(
    (result) => {
      setStatus("authenticated");
      onSignedIn(result);
    },
    [onSignedIn],
  );
  const adapter = useSiweAdapter({ serverConfig, platform, usernameRef, onVerified: finish, onError });
  return h(
    Providers,
    { wagmiConfig, queryClient, theme, adapter, status },
    h(LoginScreen, { serverConfig, identityStore, platform, t, displayName, setDisplayName, finish, onError }),
  );
}

function AccountScreen({ serverConfig, identityStore, platform, t, session, onRenamed, onIdentityRemoved, onError }) {
  const account = useAccount();
  const { disconnectAsync } = useDisconnect();
  const ensQuery = useEnsName({
    address: session.address,
    chainId: 1,
    query: { enabled: serverConfig.chainIds.includes(1) },
  });
  const [identity, setIdentity] = useState(undefined);
  const [name, setName] = useState(session.username || "");
  const [phraseShown, setPhraseShown] = useState(false);
  const [confirmForget, setConfirmForget] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    identityStore.read().then(setIdentity, (readError) => setError(errorMessage(readError)));
  }, [identityStore]);

  const deviceSession = Boolean(identity && identity.address.toLowerCase() === String(session.address).toLowerCase());

  const rename = async () => {
    setError(null);
    setBusy(true);
    try {
      const result = await signInWithIdentity({
        serverUrl: serverConfig.serverUrl,
        serverConfig,
        platform,
        identityStore,
        username: name.trim(),
      });
      onRenamed({ ...result, connector: IDENTITY_CONNECTOR_ID });
    } catch (failure) {
      setError(errorMessage(failure));
      onError(failure);
    } finally {
      setBusy(false);
    }
  };

  const forget = async () => {
    setError(null);
    setBusy(true);
    try {
      if (account.isConnected && account.connector?.id === IDENTITY_CONNECTOR_ID) await disconnectAsync();
      await identityStore.remove();
      setIdentity(null);
      setConfirmForget(false);
      onIdentityRemoved();
    } catch (failure) {
      setError(errorMessage(failure));
      onError(failure);
    } finally {
      setBusy(false);
    }
  };

  return h(
    "div",
    { className: "ls-wallet-account" },
    h(
      "section",
      { className: "ls-wallet-card" },
      h("h3", null, t("wallet/address")),
      h("div", { className: "ls-wallet-address" }, h("code", null, session.address)),
      ensQuery.data ? h("p", { className: "ls-wallet-muted" }, ensQuery.data) : null,
    ),
    h(
      "section",
      { className: "ls-wallet-card" },
      h("h3", null, t("wallet/display-name")),
      deviceSession
        ? h(
            "div",
            { className: "ls-wallet-row" },
            h("input", {
              type: "text",
              maxLength: 64,
              value: name,
              "data-wallet-field": "display-name",
              onChange: (event) => setName(event.target.value),
            }),
            h(Button, { action: "rename", primary: true, disabled: busy || name.trim() === "" || name.trim() === session.username, onClick: rename }, t("wallet/save")),
          )
        : h("p", null, session.username, h("br"), h("span", { className: "ls-wallet-muted" }, t("wallet/rename-with-wallet"))),
    ),
    identity
      ? h(
          "section",
          { className: "ls-wallet-card" },
          h("h3", null, t("wallet/identity")),
          h("p", { className: "ls-wallet-muted" }, t("wallet/identity-desc")),
          h("div", { className: "ls-wallet-address" }, h("code", { title: identity.address }, shortAddress(identity.address))),
          phraseShown ? h(PhraseWords, { phrase: identity.phrase }) : null,
          h(
            "div",
            { className: "ls-wallet-row" },
            h(Button, { action: "toggle-phrase", onClick: () => setPhraseShown((shown) => !shown) }, t(phraseShown ? "wallet/hide-phrase" : "wallet/show-phrase")),
            phraseShown ? h(Button, { action: "copy-phrase", onClick: () => copyText(identity.phrase) }, t("wallet/copy-phrase")) : null,
            confirmForget
              ? h(Button, { action: "confirm-forget-identity", disabled: busy, onClick: forget }, t("wallet/forget-identity-confirm"))
              : h(Button, { action: "forget-identity", disabled: busy, onClick: () => setConfirmForget(true) }, t("wallet/forget-identity")),
            confirmForget ? h(Button, { action: "cancel", onClick: () => setConfirmForget(false) }, t("wallet/cancel")) : null,
          ),
        )
      : null,
    account.isConnected && account.connector && account.connector.id !== IDENTITY_CONNECTOR_ID
      ? h(
          "section",
          { className: "ls-wallet-card" },
          h("h3", null, t("wallet/connected-wallet")),
          h("p", null, account.connector.name, " ", h("code", null, shortAddress(account.address))),
          h(Button, { action: "disconnect-wallet", disabled: busy, onClick: () => disconnectAsync().catch((failure) => setError(errorMessage(failure))) }, t("wallet/disconnect")),
        )
      : null,
    error ? h("div", { className: "ls-wallet-error", role: "alert" }, error) : null,
  );
}

export function AccountApp({ context, identityStore, platform, t, theme, session, onRenamed, onIdentityRemoved, onError }) {
  const { serverConfig, wagmiConfig, queryClient } = context;
  const usernameRef = useRef(session.username);
  const adapter = useSiweAdapter({ serverConfig, platform, usernameRef, onVerified: onRenamed, onError });
  return h(
    Providers,
    { wagmiConfig, queryClient, theme, adapter, status: "authenticated" },
    h(AccountScreen, { serverConfig, identityStore, platform, t, session, onRenamed, onIdentityRemoved, onError }),
  );
}

/** Loads the server configuration before rendering `App`. */
export function Boot({ loadContext, App, t, ...rest }) {
  const [state, setState] = useState({ context: null, error: null, attempt: 0 });
  useEffect(() => {
    let cancelled = false;
    loadContext().then(
      (context) => {
        if (!cancelled) setState((current) => ({ ...current, context, error: null }));
      },
      (failure) => {
        if (!cancelled) setState((current) => ({ ...current, error: failure }));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [loadContext, state.attempt]);
  if (state.error) {
    return h(
      "div",
      { className: "ls-wallet-login" },
      h("div", { className: "ls-wallet-error", role: "alert" }, t("wallet/server-unavailable", errorMessage(state.error))),
      h(Button, { action: "retry", onClick: () => setState({ context: null, error: null, attempt: state.attempt + 1 }) }, t("wallet/retry")),
    );
  }
  if (!state.context) {
    return h("div", { className: "ls-wallet-login" }, h("p", { className: "ls-wallet-muted" }, t("wallet/loading")));
  }
  return h(App, { context: state.context, t, ...rest });
}
