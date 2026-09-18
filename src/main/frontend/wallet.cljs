(ns frontend.wallet
  "The wallet bundle (RainbowKit, wagmi and viem, built by
   vite.wallet.config.mjs) loaded on demand, and the identity store each
   platform hands it: localStorage on the web and on mobile, an encrypted
   file behind IPC on the desktop."
  (:require [electron.ipc :as ipc]
            [frontend.config :as config]
            [frontend.context.i18n :refer [t]]
            [frontend.loader :as loader]
            [frontend.mobile.util :as mobile-util]
            [frontend.state :as state]
            [frontend.util :as util]
            [promesa.core :as p]))

(defonce ^:private *bundle (atom nil))

(defn- add-stylesheet!
  []
  (when-not (js/document.querySelector "link[data-wallet-css]")
    (let [link (js/document.createElement "link")]
      (set! (.-rel link) "stylesheet")
      (set! (.-href link) "./js/wallet.css")
      (.setAttribute link "data-wallet-css" "true")
      (.appendChild js/document.head link))))

(defn <load!
  "Resolves to the bundle's API (window.logseqWallet) once it is on the page."
  []
  (or @*bundle
      (let [loading (p/create
                     (fn [resolve reject]
                       (add-stylesheet!)
                       (-> (loader/load "./js/wallet.js"
                                        (fn []
                                          (if-let [api (.-logseqWallet js/window)]
                                            (resolve api)
                                            (reject (ex-info "wallet bundle did not register window.logseqWallet" {})))))
                           (.addErrback (fn [error] (reject error))))))
            bundle (p/catch loading (fn [error]
                                      (reset! *bundle nil)
                                      (p/rejected error)))]
        (reset! *bundle bundle)
        bundle)))

(defn platform
  []
  (cond
    (util/electron?) "electron"
    (mobile-util/native-platform?) "mobile"
    :else "web"))

(def ^:private storage-key "wallet-identity")

(defn- read-local-identity
  []
  (p/resolved (when-let [text (js/localStorage.getItem storage-key)]
                (js/JSON.parse text))))

(defn- write-local-identity
  [identity]
  (js/localStorage.setItem storage-key (js/JSON.stringify identity))
  (p/resolved nil))

(defn- remove-local-identity
  []
  (js/localStorage.removeItem storage-key)
  (p/resolved nil))

(defn- read-electron-identity
  []
  (p/let [identity (ipc/ipc :identity/read)]
    (when identity (clj->js identity))))

(defn- write-electron-identity
  [identity]
  (ipc/ipc :identity/write (js->clj identity :keywordize-keys true)))

(defn- remove-electron-identity
  []
  (ipc/ipc :identity/remove))

(defn identity-store
  "The store the bundle reads and writes this device's identity through:
   {phrase, address, displayName} or nothing."
  []
  (if (util/electron?)
    #js {:read read-electron-identity
         :write write-electron-identity
         :remove remove-electron-identity}
    #js {:read read-local-identity
         :write write-local-identity
         :remove remove-local-identity}))

(defn <has-identity?
  []
  (p/let [identity (.read ^js (identity-store))]
    (some? identity)))

(defn- translate
  [key & args]
  (apply t (keyword key) args))

(defn- options
  [extra]
  (clj->js (merge {:serverUrl (config/sync-server-url)
                   :identityStore (identity-store)
                   :platform (platform)
                   :theme (if (= "dark" (state/get-state :ui/theme)) "dark" "light")
                   :t translate}
                  extra)))

(defn <mount-login!
  "Renders the sign-in screen into `element`. `on-signed-in` receives a JS
   object {accessToken, expiresIn, address, connector}; the result's
   `unmount` ends the screen."
  [element {:keys [on-signed-in on-error]}]
  (p/let [^js wallet (<load!)]
    (.mountLogin wallet element (options {:onSignedIn on-signed-in
                                          :onError on-error}))))

(defn <mount-account!
  "Renders the account screen for the signed-in `session` {:address :username}."
  [element {:keys [session on-renamed on-identity-removed on-error]}]
  (p/let [^js wallet (<load!)]
    (.mountAccount wallet element (options {:session (clj->js session)
                                            :onRenamed on-renamed
                                            :onIdentityRemoved on-identity-removed
                                            :onError on-error}))))

(defn <renew-session!
  "Signs in again with this device's identity; resolves to
   {:access-token :expires-in :address}."
  [{:keys [username]}]
  (p/let [^js wallet (<load!)
          ^js result (.renewSession wallet (options {:username username}))]
    {:access-token (.-accessToken result)
     :expires-in (.-expiresIn result)
     :address (.-address result)}))

(defn <sign-out!
  "Drops wallet connections when the bundle was loaded; the identity stays."
  []
  (if-let [bundle @*bundle]
    (p/let [^js wallet bundle]
      (.signOut wallet))
    (p/resolved nil)))
