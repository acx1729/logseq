(ns logseq.db-sync.malli-schema-test
  (:require [cljs.test :refer [deftest is testing]]
            [logseq.db-sync.malli-schema :as db-sync-schema]))

(def ^:private request-samples
  {:graphs/create {:graph-name "Demo"}
   :graph-members/create {:user-id "0x1111111111111111111111111111111111111111"}
   :graph-members/update {:role "member"}
   :sync/tx-batch {:t-before 0 :txs []}})

(defn- coerce-request
  [schema-key body]
  ((get db-sync-schema/http-request-coercers schema-key) body))

(deftest http-request-client-revision-is-optional-test
  (doseq [[schema-key body] request-samples]
    (testing schema-key
      (is (= body (coerce-request schema-key body))))))

(deftest tx-batch-request-client-revision-accepts-string-test
  (let [body' (assoc (:sync/tx-batch request-samples)
                     :client-revision "test-revision")]
    (is (= body' (coerce-request :sync/tx-batch body')))))

(deftest ws-tx-batch-client-revision-accepts-string-test
  (let [body {:type "tx/batch"
              :t-before 0
              :txs []
              :client-revision "test-revision"}]
    (is (= body (db-sync-schema/ws-client-message-coercer body)))))

(deftest tx-batch-request-client-revision-rejects-non-string-test
  (is (thrown? js/Error
               (coerce-request :sync/tx-batch
                               (assoc (:sync/tx-batch request-samples)
                                      :client-revision 42)))))
