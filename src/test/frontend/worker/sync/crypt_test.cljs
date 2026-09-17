(ns frontend.worker.sync.crypt-test
  (:require [cljs.test :refer [deftest is async]]
            [frontend.common.crypt :as crypt]
            [frontend.worker.state :as worker-state]
            [frontend.worker.sync.crypt :as sync-crypt]
            [frontend.worker.sync.util :as sync-util]
            [logseq.db :as ldb]
            [promesa.core :as p]))

(defn- <encrypt-text-for-snapshot
  [aes-key value]
  (p/let [encrypted (crypt/<encrypt-text aes-key (ldb/write-transit-str value))]
    (ldb/write-transit-str encrypted)))

(defn- bytes->base64
  [^js bytes]
  (js/btoa (.reduce bytes (fn [acc b] (str acc (js/String.fromCharCode b))) "")))

(defn- with-sync-config
  "Runs `f` with the worker's sync config pointed at a test server and every
  cached graph key forgotten; restores the config afterwards."
  [f]
  (let [config-prev @worker-state/*db-sync-config]
    (reset! worker-state/*db-sync-config {:http-base "https://sync.example.test"})
    (sync-crypt/forget-graph-aes-keys!)
    (-> (f)
        (p/finally (fn [& _]
                     (sync-crypt/forget-graph-aes-keys!)
                     (reset! worker-state/*db-sync-config config-prev))))))

(deftest ensure-graph-aes-key-fetches-the-key-once-per-session-test
  (async done
         (let [raw-key (js/crypto.getRandomValues (js/Uint8Array. 32))
               calls* (atom [])]
           (-> (with-sync-config
                 (fn []
                   (p/with-redefs [sync-util/fetch-json (fn [url opts schema]
                                                          (swap! calls* conj [url (:method opts) schema])
                                                          (p/resolved {:key (bytes->base64 raw-key)}))]
                     (p/let [[first-key second-key] (p/all [(sync-crypt/<ensure-graph-aes-key "graph-1")
                                                            (sync-crypt/<ensure-graph-aes-key "graph-1")])
                             third-key (sync-crypt/<ensure-graph-aes-key "graph-1")
                             exported (crypt/<export-aes-key third-key)]
                       (is (= [["https://sync.example.test/graphs/graph-1/key" "GET" {:response-schema :graphs/key}]]
                              @calls*))
                       (is (identical? first-key second-key))
                       (is (identical? first-key third-key))
                       (is (= (vec raw-key) (vec exported)))))))
               (p/then (fn [] (done)))
               (p/catch (fn [e]
                          (is false (str e))
                          (done)))))))

(deftest ensure-graph-aes-key-retries-after-a-failed-fetch-test
  (async done
         (let [raw-key (js/crypto.getRandomValues (js/Uint8Array. 32))
               calls* (atom 0)]
           (-> (with-sync-config
                 (fn []
                   (p/with-redefs [sync-util/fetch-json (fn [_url _opts _schema]
                                                          (swap! calls* inc)
                                                          (if (= 1 @calls*)
                                                            (p/rejected (ex-info "db-sync request failed" {:status 403}))
                                                            (p/resolved {:key (bytes->base64 raw-key)})))]
                     (-> (sync-crypt/<ensure-graph-aes-key "graph-2")
                         (p/then (fn [_] (is false "the first fetch should fail")))
                         (p/catch (fn [error]
                                    (is (= "db-sync request failed" (ex-message error)))))
                         (p/then (fn [_]
                                   (p/let [aes-key (sync-crypt/<ensure-graph-aes-key "graph-2")]
                                     (is (instance? js/CryptoKey aes-key))
                                     (is (= 2 @calls*)))))))))
               (p/then (fn [] (done)))
               (p/catch (fn [e]
                          (is false (str e))
                          (done)))))))

(deftest ensure-graph-aes-key-rejects-keys-of-the-wrong-size-test
  (async done
         (-> (with-sync-config
               (fn []
                 (p/with-redefs [sync-util/fetch-json (fn [_url _opts _schema]
                                                        (p/resolved {:key (bytes->base64 (js/Uint8Array. 5))}))]
                   (-> (sync-crypt/<ensure-graph-aes-key "graph-3")
                       (p/then (fn [_] (is false "a 5 byte key must be refused")))
                       (p/catch (fn [error]
                                  (is (re-find #"invalid-field" (ex-message error)))
                                  (is (= :key (:field (ex-data error))))))))))
             (p/then (fn [] (done)))
             (p/catch (fn [e]
                        (is false (str e))
                        (done))))))

(deftest ensure-graph-aes-key-needs-a-server-and-a-graph-id-test
  (async done
         (let [config-prev @worker-state/*db-sync-config]
           (reset! worker-state/*db-sync-config {:http-base nil :ws-url nil})
           (sync-crypt/forget-graph-aes-keys!)
           (-> (sync-crypt/<ensure-graph-aes-key "graph-4")
               (p/then (fn [_] (is false "no server configured")))
               (p/catch (fn [error]
                          (is (= :http-base (:field (ex-data error))))))
               (p/then (fn [_]
                         (is (thrown? js/Error (sync-crypt/<ensure-graph-aes-key nil)))))
               (p/finally (fn [& _]
                            (reset! worker-state/*db-sync-config config-prev)
                            (done)))))))

(deftest encrypt-and-decrypt-tx-data-roundtrip-test
  (async done
         (-> (p/let [aes-key (crypt/<generate-aes-key)
                     tx-data [[:db/add 1 :block/title "Title" 1000]
                              [:db/add 1 :block/name "name" 1000]
                              [:db/add 1 :block/order "a0" 1000]]
                     encrypted (sync-crypt/<encrypt-tx-data aes-key tx-data)
                     decrypted (sync-crypt/<decrypt-tx-data aes-key encrypted)]
               (is (not= "Title" (nth (first encrypted) 3)))
               (is (= "a0" (nth (nth encrypted 2) 3)))
               (is (= tx-data decrypted))
               (done))
             (p/catch (fn [e]
                        (is false (str e))
                        (done))))))

(deftest decrypt-snapshot-datoms-test
  (async done
         (-> (p/let [aes-key (crypt/<generate-aes-key)
                     encrypted-title (<encrypt-text-for-snapshot aes-key "Title")
                     encrypted-name (<encrypt-text-for-snapshot aes-key "name")
                     datoms [{:e 1 :a :block/title :v encrypted-title :tx 1000 :added true}
                             {:e 1 :a :block/name :v encrypted-name :tx 1000 :added true}]
                     decrypted (sync-crypt/<decrypt-snapshot-datoms-batch aes-key datoms)]
               (is (= "Title" (:v (first decrypted))))
               (is (= "name" (:v (second decrypted))))
               (done))
             (p/catch (fn [e]
                        (is false (str e))
                        (done))))))

(deftest ^:fix-me decrypt-snapshot-rows-test
  (async done
         (-> (p/let [aes-key (crypt/<generate-aes-key)
                     encrypted-title (<encrypt-text-for-snapshot aes-key "Title")
                     encrypted-name (<encrypt-text-for-snapshot aes-key "name")
                     raw-content (ldb/write-transit-str
                                  {:keys [[1 :block/title encrypted-title 1000]
                                          [1 :block/title encrypted-name 1000]]})
                     rows [["addr-1" raw-content nil]]
                     [[_ decrypted-content _]] (sync-crypt/<decrypt-snapshot-rows-batch aes-key rows)
                     keys (:keys (ldb/read-transit-str decrypted-content))]
               (is (= "Title" (nth (first keys) 2)))
               (is (= "name" (nth (second keys) 2)))
               (done))
             (p/catch (fn [e]
                        (is false (str e))
                        (done))))))

(deftest decrypt-text-value-legacy-plaintext-test
  (async done
         (-> (p/let [aes-key (crypt/<generate-aes-key)
                     plaintext "$$$favorites"
                     encrypted (crypt/<encrypt-uint8array aes-key (.encode (js/TextEncoder.) plaintext))
                     encrypted-str (ldb/write-transit-str encrypted)
                     decrypted (sync-crypt/<decrypt-text-value aes-key encrypted-str)]
               (is (= plaintext decrypted))
               (done))
             (p/catch (fn [e]
                        (is false (str e))
                        (done))))))
