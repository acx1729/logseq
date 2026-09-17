(ns logseq.db-sync.worker.auth
  (:require [clojure.string :as string]
            [promesa.core :as p]))

(defn- bearer-token [auth-header]
  (when (and (string? auth-header) (string/starts-with? auth-header "Bearer "))
    (subs auth-header 7)))

(defn token-from-request [request]
  (or (bearer-token (.get (.-headers request) "authorization"))
      (let [url (js/URL. (.-url request))]
        (.get (.-searchParams url) "token"))))

(defn auth-claims
  "Resolves to the verified claims of the request's bearer token (Authorization
  header or `?token=`), or nil when the request carries no token or the token
  is refused. Rejects only when the verifier itself fails."
  [request ^js env]
  (let [token (token-from-request request)
        verify (aget env "DB_SYNC_VERIFY_TOKEN")]
    (cond
      (not (string? token))
      (p/resolved nil)

      (not (fn? verify))
      (throw (ex-info "DB_SYNC_VERIFY_TOKEN is not configured" {}))

      :else
      (p/let [claims (verify token)]
        (when (object? claims)
          claims)))))
