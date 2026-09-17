(ns logseq.db-sync.node.keys
  "Graph key custody on the Node adapter. Every graph gets one AES-256 key when
  it is created; members fetch it over the authenticated key route and it never
  enters the index database. The store and the OpenBao session it may use are
  built here from the configuration; the store itself lives in worker/auth
  (JavaScript) next to the Transit signer that shares the session."
  (:require ["path" :as node-path]))

(def ^:private auth-lib
  (js/require (node-path/join js/__dirname ".." "auth" "index.js")))

(defn openbao-needed?
  "True when the token signer or the key store talks to OpenBao."
  [{:keys [token-signer key-store]}]
  (or (= "transit" token-signer)
      (= "openbao" key-store)))

(defn create-openbao-client
  "One OpenBao session, shared by the Transit signer and the KV key store:
  a static token for development or an AppRole login in production."
  [{:keys [bao-addr bao-token bao-role-id bao-secret-id bao-secret-id-file]}]
  (.createOpenBaoClient auth-lib
                        #js {:baseUrl bao-addr
                             :token bao-token
                             :roleId bao-role-id
                             :secretId bao-secret-id
                             :secretIdFile bao-secret-id-file}))

(defn create-key-store
  "Graph key store from the normalized configuration: files under the data
  directory for development and CI, or an OpenBao KV v2 mount in production."
  [{:keys [key-store key-store-dir bao-kv-mount bao-kv-prefix]} openbao-client]
  (.createKeyStore auth-lib
                   (if (= "file" key-store)
                     #js {:kind "file" :dir key-store-dir}
                     #js {:kind "openbao"
                          :client openbao-client
                          :mount bao-kv-mount
                          :prefix bao-kv-prefix})))
