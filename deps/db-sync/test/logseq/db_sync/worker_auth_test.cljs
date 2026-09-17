(ns logseq.db-sync.worker-auth-test
  (:require [cljs.test :refer [async deftest is]]
            [logseq.db-sync.worker.auth :as auth]
            [promesa.core :as p]))

(defn- request-with-token [token]
  (js/Request. "http://localhost/graphs"
               #js {:headers #js {"authorization" (str "Bearer " token)}}))

(defn- env-with-verifier [verify]
  #js {"DB_SYNC_VERIFY_TOKEN" verify})

(deftest token-from-request-reads-bearer-header-or-query-param-test
  (is (= "abc" (auth/token-from-request (request-with-token "abc"))))
  (is (= "xyz" (auth/token-from-request (js/Request. "http://localhost/sync/graph-1?token=xyz"))))
  (is (nil? (auth/token-from-request (js/Request. "http://localhost/graphs")))))

(deftest auth-claims-returns-verified-claims-test
  (async done
         (-> (p/let [claims (auth/auth-claims (request-with-token "good")
                                              (env-with-verifier
                                               (fn [token]
                                                 (js/Promise.resolve #js {"sub" (str "user:" token)}))))]
               (is (= "user:good" (aget claims "sub"))))
             (p/then (fn [] (done)))
             (p/catch (fn [error]
                        (is false (str error))
                        (done))))))

(deftest auth-claims-returns-nil-without-token-test
  (async done
         (-> (p/let [claims (auth/auth-claims (js/Request. "http://localhost/graphs")
                                              (env-with-verifier
                                               (fn [_token]
                                                 (throw (ex-info "verifier must not run" {})))))]
               (is (nil? claims)))
             (p/then (fn [] (done)))
             (p/catch (fn [error]
                        (is false (str error))
                        (done))))))

(deftest auth-claims-returns-nil-for-refused-token-test
  (async done
         (-> (p/let [claims (auth/auth-claims (request-with-token "forged")
                                              (env-with-verifier
                                               (fn [_token]
                                                 (js/Promise.resolve nil))))]
               (is (nil? claims)))
             (p/then (fn [] (done)))
             (p/catch (fn [error]
                        (is false (str error))
                        (done))))))

(deftest auth-claims-propagates-verifier-failure-test
  (async done
         (-> (auth/auth-claims (request-with-token "any")
                               (env-with-verifier
                                (fn [_token]
                                  (p/rejected (ex-info "openbao unreachable" {})))))
             (p/then (fn [_]
                       (is false "expected rejection when the verifier fails")
                       (done)))
             (p/catch (fn [error]
                        (is (= "openbao unreachable" (ex-message error)))
                        (done))))))

(deftest auth-claims-fails-fast-without-verifier-test
  (is (thrown? js/Error (auth/auth-claims (request-with-token "any") #js {}))))
