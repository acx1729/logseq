(ns logseq.db-sync.node.auth
  "HTTP surface of wallet sign-in on the Node adapter. Message verification,
  token minting, the PKCE code store and the hosted page live in worker/auth
  (JavaScript); this namespace builds that service from the configuration and
  maps its results and refusals to responses."
  (:require ["path" :as node-path]
            [clojure.string :as string]
            [logseq.db-sync.common :as common]
            [logseq.db-sync.index :as index]
            [logseq.db-sync.platform.core :as platform]
            [promesa.core :as p]))

(def ^:private auth-lib
  (js/require (node-path/join js/__dirname ".." "auth" "index.js")))

(defn auth-migrations
  "Index migrations owned by the auth store; applied through index/<index-init!."
  []
  (mapv (fn [^js migration]
          {:id (.-id migration)
           :statements (vec (.-statements migration))})
        (.-AUTH_MIGRATIONS auth-lib)))

(defn create-signer
  "Token signer from the normalized configuration: a PEM key file for
  development and CI, or an OpenBao Transit key over the shared OpenBao
  session in production."
  [{:keys [token-signer token-signing-key-file bao-transit-mount bao-transit-key]} openbao-client]
  (.createSigner auth-lib
                 (if (= "file" token-signer)
                   #js {:kind "file" :keyFile token-signing-key-file}
                   #js {:kind "transit"
                        :client openbao-client
                        :mount bao-transit-mount
                        :keyName bao-transit-key})))

(defn create-service
  "Builds the auth service on the index database. Its tables come from
  `auth-migrations`, so the migrations must have run first."
  [cfg signer index-db]
  (.createAuthService auth-lib
                      #js {:config #js {:issuer (:token-issuer cfg)
                                        :audience (:token-audience cfg)
                                        :tokenTtlS (:token-ttl-s cfg)
                                        :siweDomains (to-array (:siwe-domains cfg))
                                        :siweChainIds (to-array (:siwe-chain-ids cfg))
                                        :redirectUris (to-array (:siwe-redirect-uris cfg))
                                        :siweStatement (:siwe-statement cfg)
                                        :appName (:app-name cfg)}
                           :signer signer
                           :store (.createAuthStore auth-lib index-db)}))

(defn- client-ip
  [request trust-proxy?]
  (let [headers (.-headers request)
        forwarded (when trust-proxy? (.get headers "x-forwarded-for"))
        forwarded-ip (when (string? forwarded)
                       (some-> (string/split forwarded #",") last string/trim not-empty))]
    (or forwarded-ip (.get headers "x-db-sync-remote-address"))))

(defn- <request-body [request]
  (p/let [text (.text request)]
    (.parseBody auth-lib (.get (.-headers request) "content-type") text)))

(defn- query-params [^js url]
  (let [params (js-obj)]
    (.forEach (.-searchParams url) (fn [value k] (aset params k value)))
    params))

(defn- error-response [^js error]
  (if (= "AuthError" (.-name error))
    (common/json-response #js {:error (.-code error)
                               :error_description (.-message error)}
                          (.-status error))
    (throw error)))

(defn- <handle-route
  [{:keys [^js service db request ^js url cfg]}]
  (let [path (.-pathname url)
        method (.-method request)
        ip (client-ip request (:trust-proxy? cfg))]
    (cond
      (and (= path "/auth/nonce") (= method "GET"))
      (common/json-response (.issueNonce service #js {:ip ip}))

      (and (= path "/auth/siwe") (= method "POST"))
      (p/let [body (<request-body request)
              ^js result (.signIn service #js {:ip ip :body body})
              _ (index/<user-upsert! db (.-user result))]
        (if (= "code" (.-kind result))
          (common/json-response #js {:code (.-code result)})
          (common/json-response (.tokenResponse service result))))

      (and (= path "/auth/token") (= method "POST"))
      (p/let [body (<request-body request)
              result (.exchangeCode service #js {:ip ip :body body})]
        (common/json-response (.tokenResponse service result)))

      (and (= path "/auth/jwks.json") (= method "GET"))
      (p/let [jwks (.jwks service)]
        (common/json-response jwks))

      (and (= path "/auth/siwe/start") (= method "GET"))
      (let [^js page (.signInPage service (query-params url))]
        (platform/response (.-html page) #js {:status 200 :headers (.-headers page)}))

      :else
      (common/json-response {:error "not found"} 404))))

(defn handle
  "Serves /auth/*. Resolves to a Response; refusals become JSON errors with
  the service's status code, anything else propagates to the caller."
  [ctx]
  (-> (p/create (fn [resolve reject]
                  (try
                    (resolve (<handle-route ctx))
                    (catch :default error
                      (reject error)))))
      (p/catch error-response)))
