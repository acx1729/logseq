(ns logseq.db-sync.test-server
  "Configuration for starting the Node adapter in tests: a throwaway signing
  key on disk, graph keys as files and a local issuer, so no OpenBao is needed."
  (:require ["node:crypto" :as crypto]
            ["node:fs" :as fs]
            [logseq.db-sync.node.server :as node-server]))

(defn- write-signing-key! [dir]
  (.mkdirSync fs dir #js {:recursive true})
  (let [pair (.generateKeyPairSync crypto "rsa" #js {:modulusLength 2048})
        pem (.export (.-privateKey pair) #js {:type "pkcs8" :format "pem"})
        path (str dir "/signing-key.pem")]
    (.writeFileSync fs path pem)
    path))

(defn test-overrides
  "Adapter overrides for a fresh data directory under `prefix`."
  ([prefix] (test-overrides prefix {}))
  ([prefix extra]
   (let [dir (str prefix (random-uuid))]
     (merge {:port 0
             :data-dir dir
             :token-issuer "http://127.0.0.1"
             :token-signer "file"
             :token-signing-key-file (write-signing-key! dir)
             :key-store "file"
             :siwe-domains ["localhost" "127.0.0.1"]}
            extra))))

(defn start!
  ([prefix] (start! prefix {}))
  ([prefix extra]
   (node-server/start! (test-overrides prefix extra))))
