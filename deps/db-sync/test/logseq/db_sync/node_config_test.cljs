(ns logseq.db-sync.node-config-test
  (:require [cljs.test :refer [deftest is testing]]
            [logseq.db-sync.node.config :as config]))

(def ^:private base-config
  {:token-issuer "http://localhost:8787"
   :token-signer "file"
   :token-signing-key-file "tmp/unused-signing-key.pem"
   :key-store "file"
   :siwe-domains ["localhost:8787"]})

(defn- normalize [overrides]
  (config/normalize-config (merge base-config overrides)))

(defn- failure-message [f]
  (try
    (f)
    nil
    (catch :default e
      (ex-message e))))

(deftest normalize-config-drops-unknown-keys-test
  (let [cfg (normalize {:port 7777
                        :unknown-key "value"
                        :cognito-issuer "value"})]
    (is (= 7777 (:port cfg)))
    (is (nil? (:unknown-key cfg)))
    (is (nil? (:cognito-issuer cfg)))))

(deftest normalize-config-storage-driver-test
  (testing "sqlite storage driver accepted"
    (is (= "sqlite" (:storage-driver (normalize {:storage-driver "sqlite"})))))
  (testing "unsupported storage driver throws"
    (is (re-find #"storage driver" (failure-message #(normalize {:storage-driver "other"}))))))

(deftest normalize-config-assets-driver-test
  (testing "filesystem assets driver accepted"
    (is (= "filesystem" (:assets-driver (normalize {:assets-driver "filesystem"})))))
  (testing "unsupported assets driver throws"
    (is (re-find #"assets driver" (failure-message #(normalize {:assets-driver "s3"}))))))

(deftest normalize-config-auth-defaults-test
  (let [cfg (normalize {})]
    (is (= "logseq-sync" (:token-audience cfg)))
    (is (= (* 30 24 60 60) (:token-ttl-s cfg)))
    (is (= config/default-siwe-redirect-uris (:siwe-redirect-uris cfg)))
    (is (= [] (:siwe-chain-ids cfg)))
    (is (= "Sign in to Logseq" (:siwe-statement cfg)))
    (is (= "Logseq" (:app-name cfg)))
    (is (false? (:trust-proxy? cfg)))
    (is (= "transit" (:bao-transit-mount cfg)))
    (is (= "logseq-token" (:bao-transit-key cfg)))
    (is (= "logseq" (:bao-kv-mount cfg)))
    (is (= "graphs" (:bao-kv-prefix cfg)))
    (is (= "data/db-sync/keys" (:key-store-dir cfg)))))

(deftest normalize-config-validates-key-store-test
  (testing "file store keeps its directory under the data directory"
    (is (= "tmp/data/keys" (:key-store-dir (normalize {:data-dir "tmp/data"}))))
    (is (= "/run/keys" (:key-store-dir (normalize {:key-store-dir "/run/keys"})))))
  (testing "openbao store needs an address, credentials, mount and prefix"
    (is (re-find #"BAO_ADDR" (failure-message #(normalize {:key-store "openbao"}))))
    (is (re-find #"BAO_TOKEN" (failure-message #(normalize {:key-store "openbao"
                                                            :bao-addr "https://bao.example.test"}))))
    (is (re-find #"BAO_KV_MOUNT" (failure-message #(normalize {:key-store "openbao"
                                                               :bao-addr "https://bao.example.test"
                                                               :bao-token "root"
                                                               :bao-kv-mount " "}))))
    (is (re-find #"BAO_KV_PREFIX" (failure-message #(normalize {:key-store "openbao"
                                                                :bao-addr "https://bao.example.test"
                                                                :bao-token "root"
                                                                :bao-kv-prefix " "}))))
    (let [cfg (normalize {:key-store "OPENBAO"
                          :bao-addr "https://bao.example.test"
                          :bao-role-id "role"
                          :bao-secret-id "secret"})]
      (is (= "openbao" (:key-store cfg)))
      (is (= "logseq" (:bao-kv-mount cfg)))))
  (testing "unknown store is refused"
    (is (re-find #"DB_SYNC_KEY_STORE" (failure-message #(normalize {:key-store "vault"}))))
    (is (re-find #"DB_SYNC_KEY_STORE" (failure-message #(normalize {:key-store nil}))))))

(deftest normalize-config-requires-issuer-and-domains-test
  (is (re-find #"DB_SYNC_TOKEN_ISSUER" (failure-message #(normalize {:token-issuer nil}))))
  (is (re-find #"DB_SYNC_TOKEN_ISSUER" (failure-message #(normalize {:token-issuer "sync.example.test"}))))
  (is (re-find #"DB_SYNC_SIWE_DOMAINS" (failure-message #(normalize {:siwe-domains []}))))
  (is (re-find #"DB_SYNC_TOKEN_TTL_S" (failure-message #(normalize {:token-ttl-s 0}))))
  (is (re-find #"DB_SYNC_SIWE_REDIRECT_URIS" (failure-message #(normalize {:siwe-redirect-uris []})))))

(deftest normalize-config-validates-signer-test
  (testing "file signer needs a key file"
    (is (re-find #"DB_SYNC_TOKEN_SIGNING_KEY_FILE"
                 (failure-message #(normalize {:token-signing-key-file nil})))))
  (testing "transit signer needs an address and credentials"
    (is (re-find #"BAO_ADDR" (failure-message #(normalize {:token-signer "transit"}))))
    (is (re-find #"BAO_TOKEN" (failure-message #(normalize {:token-signer "transit"
                                                            :bao-addr "https://bao.example.test"}))))
    (let [cfg (normalize {:token-signer "TRANSIT"
                          :bao-addr "https://bao.example.test"
                          :bao-role-id "role"
                          :bao-secret-id-file "/run/secrets/bao"})]
      (is (= "transit" (:token-signer cfg)))
      (is (= "https://bao.example.test" (:bao-addr cfg)))))
  (testing "unknown signer is refused"
    (is (re-find #"DB_SYNC_TOKEN_SIGNER" (failure-message #(normalize {:token-signer "vault"}))))
    (is (re-find #"DB_SYNC_TOKEN_SIGNER" (failure-message #(normalize {:token-signer nil}))))))

(deftest normalize-config-parses-chain-ids-test
  (is (= [1 10] (:siwe-chain-ids (normalize {:siwe-chain-ids ["1" "10"]}))))
  (is (= [1] (:siwe-chain-ids (normalize {:siwe-chain-ids [1]}))))
  (is (re-find #"DB_SYNC_SIWE_CHAIN_IDS" (failure-message #(normalize {:siwe-chain-ids ["mainnet"]})))))
