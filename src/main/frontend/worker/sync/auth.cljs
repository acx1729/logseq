(ns frontend.worker.sync.auth
  "Auth and endpoint helpers for db sync."
  (:require [clojure.string :as string]
            [frontend.worker-common.util :as worker-util]
            [frontend.worker.state :as worker-state]
            [frontend.worker.sync.util :as sync-util]
            [logseq.common.util :as common-util]
            [promesa.core :as p]))

(defn ws-base-url
  [db-sync-config]
  (:ws-url db-sync-config))

(defn http-base-url
  [db-sync-config]
  (or (:http-base db-sync-config)
      (when-let [ws-url (ws-base-url db-sync-config)]
        (let [base (cond
                     (string/starts-with? ws-url "wss://")
                     (str "https://" (subs ws-url (count "wss://")))

                     (string/starts-with? ws-url "ws://")
                     (str "http://" (subs ws-url (count "ws://")))

                     :else ws-url)]
          (string/replace base #"/sync/%s$" "")))))

(defn token-expired?
  [token]
  (if-not (string? token)
    true
    (try
      (let [exp-ms (some-> token worker-util/parse-jwt :exp (* 1000))]
        (or (not (number? exp-ms))
            (<= exp-ms (common-util/time-ms))))
      (catch :default _
        true))))

(defn <resolve-ws-token
  "The token for a socket: the one in worker state, or a fresh one the UI
   thread signs in for when it is expired. A CLI-owned runtime has no UI
   thread and no identity, so it uses the token it was given."
  []
  (let [token (sync-util/auth-token)]
    (if (or (sync-util/cli-node-owner?) (not (token-expired? token)))
      (p/resolved token)
      (p/let [result (worker-state/<invoke-main-thread :thread-api/ensure-access-token)
              fresh (:access-token result)]
        (when-not (seq fresh)
          (throw (ex-info "UI thread returned no access token"
                          {:code :missing-access-token})))
        (worker-state/set-new-state! {:auth/access-token fresh})
        fresh))))

(defn get-user-uuid
  [token]
  (some-> token
          worker-util/parse-jwt
          :sub))

(defn auth-headers
  [token]
  (when-let [token* token]
    {"authorization" (str "Bearer " token*)}))

(defn with-auth-headers
  [auth-headers-f opts]
  (if-let [auth (auth-headers-f)]
    (assoc opts :headers (merge (or (:headers opts) {}) auth))
    opts))
