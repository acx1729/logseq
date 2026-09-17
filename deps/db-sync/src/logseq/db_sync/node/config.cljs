(ns logseq.db-sync.node.config
  (:require ["path" :as node-path]
            [clojure.string :as string]))

(defn- env-value [^js env k]
  (let [v (aget env k)]
    (when (seq v) v)))

(defn- parse-int [v default]
  (let [n (js/parseInt v 10)]
    (if (js/isNaN n) default n)))

(defn- parse-list [v]
  (when (string? v)
    (->> (string/split v #",")
         (map string/trim)
         (remove string/blank?)
         vec)))

(defn- truthy-env? [v]
  (contains? #{"1" "true" "yes" "on"} (string/lower-case v)))

(defn- without-nils [m]
  (into {} (remove (comp nil? val)) m))

(defn config-from-env []
  (let [env (.-env js/process)]
    (without-nils
     {:port (when-let [v (env-value env "DB_SYNC_PORT")] (parse-int v 8080))
      :base-url (env-value env "DB_SYNC_BASE_URL")
      :data-dir (env-value env "DB_SYNC_DATA_DIR")
      :storage-driver (env-value env "DB_SYNC_STORAGE_DRIVER")
      :assets-driver (env-value env "DB_SYNC_ASSETS_DRIVER")
      :log-level (env-value env "DB_SYNC_LOG_LEVEL")
      :admin-token (env-value env "DB_SYNC_ADMIN_TOKEN")
      :trust-proxy? (when-let [v (env-value env "DB_SYNC_TRUST_PROXY")] (truthy-env? v))
      :token-issuer (env-value env "DB_SYNC_TOKEN_ISSUER")
      :token-audience (env-value env "DB_SYNC_TOKEN_AUDIENCE")
      :token-ttl-s (when-let [v (env-value env "DB_SYNC_TOKEN_TTL_S")] (parse-int v nil))
      :token-signer (env-value env "DB_SYNC_TOKEN_SIGNER")
      :token-signing-key-file (env-value env "DB_SYNC_TOKEN_SIGNING_KEY_FILE")
      :key-store (env-value env "DB_SYNC_KEY_STORE")
      :key-store-dir (env-value env "DB_SYNC_KEY_STORE_DIR")
      :bao-addr (env-value env "BAO_ADDR")
      :bao-transit-mount (env-value env "BAO_TRANSIT_MOUNT")
      :bao-transit-key (env-value env "BAO_TRANSIT_KEY")
      :bao-kv-mount (env-value env "BAO_KV_MOUNT")
      :bao-kv-prefix (env-value env "BAO_KV_PREFIX")
      :bao-token (env-value env "BAO_TOKEN")
      :bao-role-id (env-value env "BAO_ROLE_ID")
      :bao-secret-id (env-value env "BAO_SECRET_ID")
      :bao-secret-id-file (env-value env "BAO_SECRET_ID_FILE")
      :siwe-domains (parse-list (env-value env "DB_SYNC_SIWE_DOMAINS"))
      :siwe-chain-ids (parse-list (env-value env "DB_SYNC_SIWE_CHAIN_IDS"))
      :siwe-statement (env-value env "DB_SYNC_SIWE_STATEMENT")
      :app-name (env-value env "DB_SYNC_APP_NAME")
      :rpc-urls (parse-list (env-value env "DB_SYNC_RPC_URLS"))
      :walletconnect-project-id (env-value env "DB_SYNC_WALLETCONNECT_PROJECT_ID")})))

(def ^:private allowed-config-keys
  [:port :base-url :data-dir :storage-driver :assets-driver :log-level :admin-token :trust-proxy?
   :token-issuer :token-audience :token-ttl-s :token-signer :token-signing-key-file
   :key-store :key-store-dir
   :bao-addr :bao-transit-mount :bao-transit-key :bao-kv-mount :bao-kv-prefix
   :bao-token :bao-role-id :bao-secret-id :bao-secret-id-file
   :siwe-domains :siwe-chain-ids :siwe-statement :app-name :rpc-urls :walletconnect-project-id])

(defn- fail! [message]
  (throw (js/Error. message)))

(defn- missing? [v]
  (or (nil? v) (and (string? v) (string/blank? v))))

(defn- validate-bao-auth!
  "OpenBao address and credentials, shared by the Transit signer and the KV
  key store; `setting` names the option that asked for them."
  [{:keys [bao-addr bao-token bao-role-id bao-secret-id bao-secret-id-file]} setting]
  (when (missing? bao-addr)
    (fail! (str "BAO_ADDR is required when " setting)))
  (when-not (or (not (missing? bao-token))
                (and (not (missing? bao-role-id))
                     (or (not (missing? bao-secret-id))
                         (not (missing? bao-secret-id-file)))))
    (fail! "OpenBao auth needs BAO_TOKEN, or BAO_ROLE_ID with BAO_SECRET_ID or BAO_SECRET_ID_FILE")))

(defn- validate-signer!
  [{:keys [token-signer token-signing-key-file bao-transit-key] :as cfg}]
  (case token-signer
    "file"
    (when (missing? token-signing-key-file)
      (fail! "DB_SYNC_TOKEN_SIGNING_KEY_FILE is required when DB_SYNC_TOKEN_SIGNER=file"))

    "transit"
    (do
      (validate-bao-auth! cfg "DB_SYNC_TOKEN_SIGNER=transit")
      (when (missing? bao-transit-key)
        (fail! "BAO_TRANSIT_KEY is required when DB_SYNC_TOKEN_SIGNER=transit")))

    (fail! (str "DB_SYNC_TOKEN_SIGNER must be file or transit, got: " (pr-str token-signer)))))

(defn- validate-key-store!
  [{:keys [key-store bao-kv-mount bao-kv-prefix] :as cfg}]
  (case key-store
    "file"
    nil

    "openbao"
    (do
      (validate-bao-auth! cfg "DB_SYNC_KEY_STORE=openbao")
      (when (missing? bao-kv-mount)
        (fail! "BAO_KV_MOUNT is required when DB_SYNC_KEY_STORE=openbao"))
      (when (missing? bao-kv-prefix)
        (fail! "BAO_KV_PREFIX is required when DB_SYNC_KEY_STORE=openbao")))

    (fail! (str "DB_SYNC_KEY_STORE must be file or openbao, got: " (pr-str key-store)))))

(defn- parse-chain-ids
  "The EIP-155 chain ids sign-in messages may name; clients offer the same
  chains in their wallet setup, so at least one is required."
  [chain-ids]
  (let [parsed (mapv (fn [v] (parse-int v nil)) chain-ids)]
    (when (or (empty? parsed) (some (fn [id] (or (nil? id) (not (pos? id)))) parsed))
      (fail! (str "DB_SYNC_SIWE_CHAIN_IDS must list at least one positive integer, got: " (pr-str chain-ids))))
    parsed))

(defn- parse-rpc-urls
  "`DB_SYNC_RPC_URLS` entries of the form `<chain id>=<url>`, or a map of chain
  id to URL from overrides, each for an accepted chain id."
  [rpc-urls chain-ids]
  (let [pairs (if (map? rpc-urls)
                (seq rpc-urls)
                (map (fn [entry]
                       (let [[id url] (string/split entry #"=" 2)]
                         [(parse-int id nil) url]))
                     rpc-urls))
        accepted (set chain-ids)]
    (into {}
          (map (fn [[chain-id url]]
                 (when (nil? chain-id)
                   (fail! (str "DB_SYNC_RPC_URLS entries must be <chain id>=<url>, got: " (pr-str rpc-urls))))
                 (when-not (contains? accepted chain-id)
                   (fail! (str "DB_SYNC_RPC_URLS names chain " chain-id " which is not in DB_SYNC_SIWE_CHAIN_IDS")))
                 (when-not (and (string? url) (re-find #"^(https?|wss?)://" url))
                   (fail! (str "DB_SYNC_RPC_URLS entry for chain " chain-id " must be an http(s) or ws(s) URL")))
                 [chain-id url]))
          pairs)))

(defn- issuer-authority [issuer]
  (try
    (.-host (js/URL. issuer))
    (catch :default _ nil)))

(defn- validate-issuer-domain!
  "Desktop, mobile and CLI clients sign messages naming the issuer's
  authority, so the domain list must carry it."
  [{:keys [token-issuer siwe-domains]}]
  (let [authority (some-> (issuer-authority token-issuer) string/lower-case)]
    (when (missing? authority)
      (fail! "DB_SYNC_TOKEN_ISSUER must be an http(s) URL with a host"))
    (when-not (contains? (set (map string/lower-case siwe-domains)) authority)
      (fail! (str "DB_SYNC_SIWE_DOMAINS must include the issuer's host " authority)))))

(defn normalize-config [overrides]
  (let [defaults {:port 8080
                  :data-dir "data/db-sync"
                  :storage-driver "sqlite"
                  :assets-driver "filesystem"
                  :log-level "info"
                  :trust-proxy? false
                  :token-audience "logseq-sync"
                  :token-ttl-s (* 30 24 60 60)
                  :bao-transit-mount "transit"
                  :bao-transit-key "logseq-token"
                  :bao-kv-mount "logseq"
                  :bao-kv-prefix "graphs"
                  :siwe-chain-ids [1]
                  :siwe-statement "Sign in to Logseq"
                  :app-name "Logseq"
                  :rpc-urls {}}
        merged (merge defaults (config-from-env) (without-nils overrides))
        storage-driver (string/lower-case (:storage-driver merged))
        assets-driver (string/lower-case (:assets-driver merged))
        token-signer (some-> (:token-signer merged) string/lower-case)
        key-store (some-> (:key-store merged) string/lower-case)
        merged (assoc merged
                      :storage-driver storage-driver
                      :assets-driver assets-driver
                      :token-signer token-signer
                      :key-store key-store
                      :key-store-dir (if (missing? (:key-store-dir merged))
                                       (node-path/join (:data-dir merged) "keys")
                                       (:key-store-dir merged))
                      :siwe-chain-ids (parse-chain-ids (:siwe-chain-ids merged)))
        merged (assoc merged :rpc-urls (parse-rpc-urls (:rpc-urls merged) (:siwe-chain-ids merged)))]
    (when-not (#{"sqlite"} storage-driver)
      (fail! (str "unsupported storage driver: " storage-driver)))
    (when-not (#{"filesystem"} assets-driver)
      (fail! (str "unsupported assets driver: " assets-driver)))
    (when-not (and (string? (:token-issuer merged))
                   (re-find #"^https?://" (:token-issuer merged)))
      (fail! "DB_SYNC_TOKEN_ISSUER must be an http(s) URL"))
    (when (missing? (:token-audience merged))
      (fail! "DB_SYNC_TOKEN_AUDIENCE must not be blank"))
    (when-not (pos-int? (:token-ttl-s merged))
      (fail! "DB_SYNC_TOKEN_TTL_S must be a positive number of seconds"))
    (when (empty? (:siwe-domains merged))
      (fail! "DB_SYNC_SIWE_DOMAINS must list at least one domain"))
    (validate-issuer-domain! merged)
    (when (missing? (:siwe-statement merged))
      (fail! "DB_SYNC_SIWE_STATEMENT must not be blank"))
    (when (missing? (:app-name merged))
      (fail! "DB_SYNC_APP_NAME must not be blank"))
    (when (and (some? (:walletconnect-project-id merged))
               (missing? (:walletconnect-project-id merged)))
      (fail! "DB_SYNC_WALLETCONNECT_PROJECT_ID must not be blank when set"))
    (validate-signer! merged)
    (validate-key-store! merged)
    (select-keys merged allowed-config-keys)))
