(ns logseq.db-sync.worker-handler-index-test
  (:require [cljs.test :refer [async deftest is]]
            [clojure.string :as string]
            [logseq.db-sync.common :as common]
            [logseq.db-sync.index :as index]
            [logseq.db-sync.worker.auth :as auth]
            [logseq.db-sync.worker.handler.index :as index-handler]
            [promesa.core :as p]))

(defn- fake-key-store
  "In-memory graph key store shaped like worker/auth/keystore.js, recording
  every call in order."
  ([] (fake-key-store {}))
  ([{:keys [create-error]}]
   (let [keys* (atom {})
         calls* (atom [])]
     {:keys* keys*
      :calls* calls*
      :store #js {:createKey (fn [graph-id]
                               (swap! calls* conj [:create graph-id])
                               (if create-error
                                 (p/rejected create-error)
                                 (let [graph-key (js/Buffer.alloc 32 7)]
                                   (swap! keys* assoc graph-id graph-key)
                                   (p/resolved graph-key))))
                  :getKey (fn [graph-id]
                            (swap! calls* conj [:get graph-id])
                            (p/resolved (get @keys* graph-id nil)))
                  :deleteKey (fn [graph-id]
                               (swap! calls* conj [:delete graph-id])
                               (swap! keys* dissoc graph-id)
                               (p/resolved nil))}})))

(defn- env-with-key-store [key-store]
  #js {"DB_SYNC_GRAPH_KEYS" (:store key-store)})

(defn- <handle
  [{:keys [request env claims route]}]
  (index-handler/handle {:db :db
                         :env env
                         :request request
                         :claims (or claims #js {"sub" "user-1"})
                         :route route}))

(defn- <json-body [resp]
  (p/let [text (.text resp)]
    (js->clj (js/JSON.parse text) :keywordize-keys true)))

(deftest graph-access-response-with-timing-caches-result-test
  (async done
         (let [request (js/Request. "http://localhost/sync/graph-1"
                                    #js {:headers #js {"authorization" "Bearer token-cache-hit"}})
               env #js {"DB" #js {}}
               auth-count (atom 0)
               query-count (atom 0)]
           (-> (p/with-redefs [auth/auth-claims (fn [_request _env]
                                                  (swap! auth-count inc)
                                                  (p/resolved #js {"sub" "user-1"}))
                               index/<user-has-access-to-graph? (fn [_db _graph-id _user-id]
                                                                  (swap! query-count inc)
                                                                  (p/resolved true))]
                 (p/let [first-result (index-handler/graph-access-response-with-timing request env "graph-1")
                         second-result (index-handler/graph-access-response-with-timing request env "graph-1")]
                   (is (= 200 (.-status (:response first-result))))
                   (is (= 200 (.-status (:response second-result))))
                   (is (= 1 @auth-count))
                   (is (= 1 @query-count))
                   (is (false? (get-in first-result [:timing :cache-hit?])))
                   (is (true? (get-in second-result [:timing :cache-hit?])))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graph-access-response-with-timing-does-not-upsert-user-test
  (async done
         (let [request (js/Request. "http://localhost/sync/graph-2"
                                    #js {:headers #js {"authorization" "Bearer token-no-upsert"}})
               env #js {"DB" #js {}}]
           (-> (p/with-redefs [auth/auth-claims (fn [_request _env]
                                                  (p/resolved #js {"sub" "user-2"}))
                               index/<user-has-access-to-graph? (fn [_db _graph-id _user-id]
                                                                  (p/resolved true))]
                 (p/let [result (index-handler/graph-access-response-with-timing request env "graph-2")]
                   (is (= 200 (.-status (:response result))))
                   (is (= true (get-in result [:timing :access-ok?])))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graphs-list-carries-no-key-material-test
  (async done
         (let [request (js/Request. "http://localhost/graphs" #js {:method "GET"})]
           (-> (p/with-redefs [index/<index-list (fn [_db _user-id]
                                                   (p/resolved []))]
                 (p/let [resp (<handle {:request request
                                        :env #js {}
                                        :route {:handler :graphs/list
                                                :path-params {}}})
                         body (<json-body resp)]
                   (is (= 200 (.-status resp)))
                   (is (= {:graphs []} body))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graphs-create-writes-the-key-before-the-rows-test
  (async done
         (let [request (js/Request. "http://localhost/graphs" #js {:method "POST"})
               key-store (fake-key-store)
               d1-runs (atom [])]
           (-> (p/with-redefs [common/read-json (fn [_]
                                                  (p/resolved #js {"graph-name" "Graph 1"
                                                                   "schema-version" "65"}))
                               common/<d1-all (fn [& _]
                                                (p/resolved #js {:results #js []}))
                               common/get-sql-rows (fn [result]
                                                     (aget result "results"))
                               common/<d1-run (fn [_db sql & args]
                                                (swap! d1-runs conj {:sql sql
                                                                     :args args})
                                                (swap! (:calls* key-store) conj [:insert])
                                                (p/resolved {:ok true}))]
                 (p/let [resp (<handle {:request request
                                        :env (env-with-key-store key-store)
                                        :route {:handler :graphs/create
                                                :path-params {}}})
                         body (<json-body resp)
                         graph-insert (first @d1-runs)]
                   (is (= 200 (.-status resp)))
                   (is (string? (:graph-id body)))
                   (is (= true (:graph-e2ee? body)))
                   (is (= true (:graph-ready-for-use? body)))
                   (is (string/includes? (:sql graph-insert) "graph_ready_for_use"))
                   (is (= 1 (nth (:args graph-insert) 4)))
                   (is (= 1 (nth (:args graph-insert) 5)))
                   (is (= [[:create (:graph-id body)] [:insert] [:insert]] @(:calls* key-store)))
                   (is (contains? @(:keys* key-store) (:graph-id body)))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graphs-create-answers-503-without-rows-when-the-key-store-fails-test
  (async done
         (let [request (js/Request. "http://localhost/graphs" #js {:method "POST"})
               key-store (fake-key-store {:create-error (js/Error. "openbao down")})
               d1-runs (atom 0)]
           (-> (p/with-redefs [common/read-json (fn [_]
                                                  (p/resolved #js {"graph-name" "Graph 2"
                                                                   "schema-version" "65"}))
                               index/<graph-name-exists? (fn [_db _graph-name _user-id]
                                                           (p/resolved false))
                               common/<d1-run (fn [& _]
                                                (swap! d1-runs inc)
                                                (p/resolved {:ok true}))]
                 (p/let [resp (<handle {:request request
                                        :env (env-with-key-store key-store)
                                        :route {:handler :graphs/create
                                                :path-params {}}})
                         body (<json-body resp)]
                   (is (= 503 (.-status resp)))
                   (is (= "graph key store unavailable" (:error body)))
                   (is (zero? @d1-runs))
                   (is (= [:create] (mapv first @(:calls* key-store))))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graphs-create-removes-the-key-when-the-rows-fail-test
  (async done
         (let [request (js/Request. "http://localhost/graphs" #js {:method "POST"})
               key-store (fake-key-store)]
           (-> (p/with-redefs [common/read-json (fn [_]
                                                  (p/resolved #js {"graph-name" "Graph 3"
                                                                   "schema-version" "65"}))
                               index/<graph-name-exists? (fn [_db _graph-name _user-id]
                                                           (p/resolved false))
                               index/<index-upsert! (fn [& _]
                                                      (p/rejected (js/Error. "disk full")))]
                 (-> (<handle {:request request
                               :env (env-with-key-store key-store)
                               :route {:handler :graphs/create
                                       :path-params {}}})
                     (p/then (fn [_]
                               (is false "graph creation should fail")))
                     (p/catch (fn [error]
                                (is (= "disk full" (.-message error)))
                                (is (= [:create :delete] (mapv first @(:calls* key-store))))
                                (is (empty? @(:keys* key-store)))))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graphs-key-is-served-to-members-only-test
  (async done
         (let [request (js/Request. "http://localhost/graphs/graph-1/key" #js {:method "GET"})
               key-store (fake-key-store)
               route {:handler :graphs/key
                      :path-params {:graph-id "graph-1"}}
               access* (atom true)]
           (-> (p/with-redefs [index/<user-has-access-to-graph? (fn [_db _graph-id _user-id]
                                                                  (p/resolved @access*))]
                 (p/let [missing (<handle {:request request
                                           :env (env-with-key-store key-store)
                                           :route route})
                         graph-key (.createKey (:store key-store) "graph-1")
                         resp (<handle {:request request
                                        :env (env-with-key-store key-store)
                                        :route route})
                         body (<json-body resp)
                         _ (reset! access* false)
                         forbidden (<handle {:request request
                                             :env (env-with-key-store key-store)
                                             :route route})
                         anonymous (<handle {:request request
                                             :env (env-with-key-store key-store)
                                             :claims #js {}
                                             :route route})]
                   (is (= 404 (.-status missing)))
                   (is (= 200 (.-status resp)))
                   (is (= (.toString graph-key "base64") (:key body)))
                   (is (= 403 (.-status forbidden)))
                   (is (= 401 (.-status anonymous)))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graph-members-create-takes-a-wallet-address-test
  (async done
         (let [upserts (atom [])
               post (fn [body]
                      (js/Request. "http://localhost/graphs/graph-1/members"
                                   #js {:method "POST"
                                        :headers #js {"content-type" "application/json"}
                                        :body (js/JSON.stringify (clj->js body))}))
               route {:handler :graph-members/create
                      :path-params {:graph-id "graph-1"}}
               address "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"]
           (-> (p/with-redefs [index/<user-is-manager? (fn [_db _graph-id _user-id]
                                                         (p/resolved true))
                               index/<graph-member-upsert! (fn [_db graph-id member-id role invited-by]
                                                             (swap! upserts conj [graph-id member-id role invited-by])
                                                             (p/resolved true))]
                 (p/let [ok (<handle {:request (post {:user-id address}) :env #js {} :route route})
                         ok-body (<json-body ok)
                         by-email (<handle {:request (post {:email "ada@example.com"}) :env #js {} :route route})
                         short (<handle {:request (post {:user-id "0x1234"}) :env #js {} :route route})]
                   (is (= 200 (.-status ok)))
                   (is (= {:ok true} ok-body))
                   (is (= [["graph-1" (string/lower-case address) "member" "user-1"]] @upserts))
                   (is (= 400 (.-status by-email)))
                   (is (= 400 (.-status short)))
                   (is (= 1 (count @upserts)))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest graphs-delete-removes-storage-then-the-key-test
  (async done
         (let [request (js/Request. "http://localhost/graphs/graph-1" #js {:method "DELETE"})
               key-store (fake-key-store)
               env (doto (env-with-key-store key-store)
                     (aset "DB_SYNC_DELETE_GRAPH"
                           (fn [graph-id]
                             (swap! (:calls* key-store) conj [:storage graph-id])
                             (p/resolved true))))]
           (-> (p/with-redefs [index/<user-has-access-to-graph? (fn [_db _graph-id _user-id]
                                                                  (p/resolved true))
                               index/<graph-delete-metadata! (fn [_db _graph-id]
                                                               (p/resolved true))
                               index/<graph-delete-index-entry! (fn [_db _graph-id]
                                                                  (p/resolved true))]
                 (p/let [resp (<handle {:request request
                                        :env env
                                        :route {:handler :graphs/delete
                                                :path-params {:graph-id "graph-1"}}})
                         body (<json-body resp)]
                   (is (= 200 (.-status resp)))
                   (is (= {:graph-id "graph-1" :deleted true} body))
                   (is (= [[:storage "graph-1"] [:delete "graph-1"]] @(:calls* key-store)))))
               (p/then (fn []
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))
