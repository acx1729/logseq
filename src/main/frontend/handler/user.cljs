(ns frontend.handler.user
  "The signed-in session: the token the sync server minted, its claims, the
   silent renewal with the identity this device holds, and sign-out."
  (:require [clojure.string :as string]
            [electron.ipc :as ipc]
            [frontend.common.thread-api :refer [def-thread-api]]
            [frontend.common.user :as common-user]
            [frontend.state :as state]
            [frontend.util :as util]
            [frontend.wallet :as wallet]
            [goog.crypt.base64 :as base64]
            [lambdaisland.glogi :as log]
            [promesa.core :as p]))

(defn parse-jwt
  "The claims of a JWT as a map; the signature is checked by the server."
  [jwt]
  (some-> jwt
          (string/split ".")
          second
          (#(base64/decodeString % true))
          js/JSON.parse
          (js->clj :keywordize-keys true)))

(defn- parse-jwt-safe
  [jwt]
  (try
    (parse-jwt jwt)
    (catch :default _
      nil)))

(defn- valid-claims?
  [claims]
  (and (map? claims)
       (string? (:sub claims))
       (string? (:username claims))
       (number? (:exp claims))))

(defn- expires-at-ms
  [claims]
  (* 1000 (:exp claims)))

(defn- expired?
  [claims]
  (<= (expires-at-ms claims) (js/Date.now)))

(def ^:private renew-ahead-ms (* 24 60 60 1000))

(defn- renewal-due?
  "True within a day of expiry, when a device with an identity signs in again."
  [claims]
  (<= (- (expires-at-ms claims) renew-ahead-ms) (js/Date.now)))

(defn access-token
  []
  (state/get-auth-access-token))

(defn- claims
  []
  (let [parsed (some-> (access-token) parse-jwt-safe)]
    (when (valid-claims? parsed)
      parsed)))

(defn address
  "The signed-in wallet address in lowercase, or nil."
  []
  (:sub (claims)))

(defn username
  "The display name the sync server has on file for this session."
  []
  (:username (claims)))

(defn short-address
  [address']
  (str (subs address' 0 6) "…" (subs address' (- (count address') 4))))

(defn logged-in?
  []
  (let [current (claims)]
    (boolean (and current (not (expired? current))))))

(defn user-uuid
  "The uuid string this person is attributed by inside graphs, or nil."
  []
  (some-> (address) common-user/address->uuid))

;;; the session token

(def ^:private token-storage-key "access-token")

(defn- persist-token!
  "Keeps the desktop's token in ~/logseq/auth.json for the CLI."
  [token]
  (when (util/electron?)
    (-> (if token
          (ipc/ipc :session/write-token token)
          (ipc/ipc :session/remove-token))
        (p/catch (fn [error]
                   (log/warn :user/persist-token-failed {:error error}))))))

(defn- apply-token!
  [token claims']
  (state/set-auth-access-token token)
  (js/localStorage.setItem token-storage-key token)
  (persist-token! token)
  (state/set-state! :auth/current-login-user claims'))

(defn login-with-token!
  "Installs a token the sync server minted and starts the signed-in flows."
  [token]
  (let [claims' (parse-jwt-safe token)]
    (when-not (valid-claims? claims')
      (throw (ex-info "token lacks the sub, username or exp claims" {:type :invalid-token})))
    (when (expired? claims')
      (throw (ex-info "token is already expired" {:type :expired-token})))
    (apply-token! token claims')
    (state/pub-event! [:user/signed-in])))

(defn- clear-session!
  []
  (state/set-auth-access-token nil)
  (js/localStorage.removeItem token-storage-key)
  (persist-token! nil)
  (state/set-state! :auth/current-login-user :logout))

(defn logout
  []
  (clear-session!)
  (state/pub-event! [:user/logout]))

(defn <renew-session!
  "Signs in again with the identity this device holds and installs the token."
  []
  (p/let [{:keys [access-token]} (wallet/<renew-session! {:username (username)})]
    (login-with-token! access-token)
    access-token))

(defn- <renew-if-possible!
  "Renews when this device holds an identity; resolves to true when it did."
  []
  (p/let [identity? (wallet/<has-identity?)]
    (if identity?
      (p/let [_ (<renew-session!)]
        true)
      false)))

(defn <ensure-token!
  "Resolves once a token good for at least a day is installed, renewing it
   first when this device holds an identity; rejects when no valid session
   remains."
  []
  (let [current (claims)]
    (cond
      (nil? current)
      (p/rejected (ex-info "not signed in" {:type :expired-token}))

      (renewal-due? current)
      (-> (<renew-if-possible!)
          (p/catch (fn [error]
                     (log/warn :user/renew-failed {:error error})
                     false))
          (p/then (fn [_]
                    (when-not (logged-in?)
                      (throw (ex-info "session expired" {:type :expired-token}))))))

      :else
      (p/resolved nil))))

(def-thread-api :thread-api/ensure-access-token
  []
  (p/let [_ (<ensure-token!)]
    {:access-token (access-token)}))

(defn restore-session!
  "Installs the token kept in this browser profile. An expired token is
   renewed when this device holds an identity; otherwise the person is asked
   to sign in again."
  []
  (let [token (js/localStorage.getItem token-storage-key)
        current (some-> token parse-jwt-safe)]
    (cond
      (nil? token)
      nil

      (not (valid-claims? current))
      (js/localStorage.removeItem token-storage-key)

      (expired? current)
      (do
        (js/localStorage.removeItem token-storage-key)
        (-> (<renew-if-possible!)
            (p/then (fn [renewed?]
                      (when-not renewed?
                        (state/pub-event! [:user/session-expired]))))
            (p/catch (fn [error]
                       (log/warn :user/renew-failed {:error error})
                       (state/pub-event! [:user/session-expired])))))

      :else
      (do
        (apply-token! token current)
        (state/pub-event! [:user/signed-in])
        (when (renewal-due? current)
          (p/catch (<renew-if-possible!)
                   (fn [error]
                     (log/warn :user/renew-failed {:error error}))))))))

;;; graph membership

(defn get-user-type
  [repo]
  (-> (some #(when (= repo (:url %)) %) (:rtc/graphs (state/get-state)))
      :graph<->user-user-type))

(defn manager?
  [repo]
  (= (get-user-type repo) "manager"))
