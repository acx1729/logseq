(ns logseq.db-sync.worker.handler.index
  (:require [lambdaisland.glogi :as log]
            [logseq.db-sync.common :as common]
            [logseq.db-sync.index :as index]
            [logseq.db-sync.worker.auth :as auth]
            [logseq.db-sync.worker.http :as http]
            [logseq.db-sync.worker.routes.index :as routes]
            [promesa.core :as p]))

(defn- index-db [^js self]
  (let [db (.-d1 self)]
    (when-not db
      (log/error :db-sync/index-db-missing {:binding "DB"}))
    db))

(defn- admin-token-valid?
  [request ^js env]
  (let [expected (aget env "DB_SYNC_ADMIN_TOKEN")
        actual (.get (.-headers request) "x-db-sync-admin-token")]
    (and (string? expected)
         (seq expected)
         (= expected actual))))

(defn- graph-key-store
  "The graph key store the adapter injects; every graph key lives there and
  never in the index database."
  [^js env]
  (let [store (aget env "DB_SYNC_GRAPH_KEYS")]
    (when-not store
      (throw (ex-info "DB_SYNC_GRAPH_KEYS is not configured" {})))
    store))

(declare invalidate-graph-access!)

(defn- <delete-graph-storage!
  [^js env graph-id]
  (let [delete-graph-fn (aget env "DB_SYNC_DELETE_GRAPH")]
    (when-not (fn? delete-graph-fn)
      (throw (ex-info "DB_SYNC_DELETE_GRAPH is not configured" {:graph-id graph-id})))
    (delete-graph-fn graph-id)))

(defn- <delete-graph!
  "Removes the graph's rows, storage and cached access, and only then its key,
  so a failure part-way leaves the remaining data decryptable."
  [db ^js env graph-id]
  (p/do!
   (index/<graph-delete-metadata! db graph-id)
   (<delete-graph-storage! env graph-id)
   (index/<graph-delete-index-entry! db graph-id)
   (invalidate-graph-access! graph-id)
   (.deleteKey (graph-key-store env) graph-id)))

(defn- <create-graph!
  "Generates the graph key first, then the index rows. A key store failure
  answers 503 with nothing written; a row failure removes the key again."
  [db ^js env graph-id graph-name user-id schema-version graph-ready-for-use?]
  (let [^js store (graph-key-store env)]
    (p/let [key-created? (-> (.createKey store graph-id)
                             (p/then (fn [_] true))
                             (p/catch (fn [error]
                                        (log/error :db-sync/graph-key-create-failed
                                                   {:graph-id graph-id :error error})
                                        false)))]
      (if-not key-created?
        (http/error-response "graph key store unavailable" 503)
        (-> (p/do!
             (index/<index-upsert! db graph-id graph-name user-id schema-version graph-ready-for-use?)
             (index/<graph-member-upsert! db graph-id user-id "manager" user-id))
            (p/then (fn [_]
                      (http/json-response :graphs/create {:graph-id graph-id
                                                          :graph-e2ee? true
                                                          :graph-ready-for-use? graph-ready-for-use?})))
            (p/catch (fn [error]
                       (-> (.deleteKey store graph-id)
                           (p/catch (fn [key-error]
                                      (log/error :db-sync/graph-key-rollback-failed
                                                 {:graph-id graph-id :error key-error})))
                           (p/then (fn [_] (throw error)))))))))))

(defn- <revoke-member-access!
  "Makes a membership removal take effect now: forgets cached access decisions
  for the graph and closes the member's open sockets on it."
  [^js env graph-id member-id]
  (let [close-sockets-fn (aget env "DB_SYNC_CLOSE_MEMBER_SOCKETS")]
    (when-not (fn? close-sockets-fn)
      (throw (ex-info "DB_SYNC_CLOSE_MEMBER_SOCKETS is not configured" {:graph-id graph-id})))
    (invalidate-graph-access! graph-id)
    (close-sockets-fn graph-id member-id)))

(defn- <safe-user-activity-touch!
  [db user-id]
  (if (string? user-id)
    (try
      (-> (index/<user-activity-touch! db user-id)
          (p/catch (fn [error]
                     (log/warn :db-sync/activity-touch-user-failed
                               {:user-id user-id
                                :error error})
                     nil)))
      (catch :default error
        (log/warn :db-sync/activity-touch-user-failed
                  {:user-id user-id
                   :error error})
        (p/resolved nil)))
    (p/resolved nil)))

(defn- <safe-graph-activity-touch!
  [db graph-id]
  (if (string? graph-id)
    (try
      (-> (index/<graph-activity-touch! db graph-id)
          (p/catch (fn [error]
                     (log/warn :db-sync/activity-touch-graph-failed
                               {:graph-id graph-id
                                :error error})
                     nil)))
      (catch :default error
        (log/warn :db-sync/activity-touch-graph-failed
                  {:graph-id graph-id
                   :error error})
        (p/resolved nil)))
    (p/resolved nil)))

(defn ^:large-vars/cleanup-todo handle [{:keys [db ^js env request claims route]}]
  (let [path-params (:path-params route)
        graph-id (:graph-id path-params)
        member-id (:member-id path-params)
        user-id (some-> claims (aget "sub"))]
    (case (:handler route)
      :graphs/list
      (if (string? user-id)
        (p/let [graphs (index/<index-list db user-id)]
          (http/json-response :graphs/list {:graphs graphs}))
        (http/unauthorized))

      :graphs/create
      (.then (common/read-json request)
             (fn [result]
               (if (nil? result)
                 (http/bad-request "missing body")
                 (let [body (js->clj result :keywordize-keys true)
                       body (http/coerce-http-request :graphs/create body)
                       graph-id (str (random-uuid))]
                   (cond
                     (not (string? user-id))
                     (http/unauthorized)

                     (nil? body)
                     (http/bad-request "invalid body")

                     :else
                     (p/let [{:keys [graph-name schema-version graph-ready-for-use?]} body
                             graph-ready-for-use? (if (nil? graph-ready-for-use?) true (true? graph-ready-for-use?))
                             name-exists? (index/<graph-name-exists? db graph-name user-id)]
                       (if name-exists?
                         (http/bad-request "duplicate graph name")
                         (<create-graph! db env graph-id graph-name user-id schema-version graph-ready-for-use?))))))))

      :graphs/access
      (cond
        (not (string? user-id))
        (http/unauthorized)

        :else
        (p/let [owns? (index/<user-has-access-to-graph? db graph-id user-id)]
          (if owns?
            (http/json-response :graphs/access {:ok true})
            (http/forbidden))))

      :graphs/key
      (cond
        (not (string? user-id))
        (http/unauthorized)

        :else
        (p/let [access? (index/<user-has-access-to-graph? db graph-id user-id)]
          (if-not access?
            (http/forbidden)
            (p/let [graph-key (.getKey (graph-key-store env) graph-id)]
              (if (nil? graph-key)
                (http/error-response "graph key not found" 404)
                (http/json-response :graphs/key {:key (.toString graph-key "base64")}))))))

      :graph-members/list
      (cond
        (not (string? user-id))
        (http/unauthorized)

        :else
        (p/let [can-access? (index/<user-has-access-to-graph? db graph-id user-id)]
          (if (not can-access?)
            (http/forbidden)
            (p/let [members (index/<graph-members-list db graph-id)]
              (http/json-response :graph-members/list {:members members})))))

      :graph-members/create
      (cond
        (not (string? user-id))
        (http/unauthorized)

        :else
        (.then (common/read-json request)
               (fn [result]
                 (if (nil? result)
                   (http/bad-request "missing body")
                   (let [body (js->clj result :keywordize-keys true)
                         body (http/coerce-http-request :graph-members/create body)
                         member-id (:user-id body)
                         email (:email body)
                         role (or (:role body) "member")]
                     (cond
                       (nil? body)
                       (http/bad-request "invalid body")

                       (and (not (string? member-id))
                            (not (string? email)))
                       (http/bad-request "invalid user")

                       :else
                       (p/let [manager? (index/<user-is-manager? db graph-id user-id)
                               resolved-id (if (string? member-id)
                                             (p/resolved member-id)
                                             (index/<user-id-by-email db email))]
                         (if (not manager?)
                           (http/forbidden)
                           (if-not (string? resolved-id)
                             (http/bad-request "user not found")
                             (p/let [_ (index/<graph-member-upsert! db graph-id resolved-id role user-id)]
                               (http/json-response :graph-members/create {:ok true})))))))))))

      :graph-members/update
      (cond
        (not (string? user-id))
        (http/unauthorized)

        (not (string? member-id))
        (http/bad-request "invalid user id")

        :else
        (.then (common/read-json request)
               (fn [result]
                 (if (nil? result)
                   (http/bad-request "missing body")
                   (let [body (js->clj result :keywordize-keys true)
                         body (http/coerce-http-request :graph-members/update body)
                         role (:role body)]
                     (cond
                       (nil? body)
                       (http/bad-request "invalid body")

                       :else
                       (p/let [manager? (index/<user-is-manager? db graph-id user-id)]
                         (if (not manager?)
                           (http/forbidden)
                           (p/let [_ (index/<graph-member-update-role! db graph-id member-id role)]
                             (http/json-response :graph-members/update {:ok true}))))))))))

      :graph-members/delete
      (cond
        (not (string? user-id))
        (http/unauthorized)

        (not (string? member-id))
        (http/bad-request "invalid user id")

        :else
        (p/let [manager? (index/<user-is-manager? db graph-id user-id)
                target-role (index/<graph-member-role db graph-id member-id)
                self-leave? (and (= user-id member-id)
                                 (= "member" target-role))]
          (cond
            (and manager? (not= "manager" target-role))
            (p/let [_ (index/<graph-member-delete! db graph-id member-id)
                    _ (<revoke-member-access! env graph-id member-id)]
              (http/json-response :graph-members/delete {:ok true}))

            self-leave?
            (p/let [_ (index/<graph-member-delete! db graph-id member-id)
                    _ (<revoke-member-access! env graph-id member-id)]
              (http/json-response :graph-members/delete {:ok true}))

            :else
            (http/forbidden))))

      :graphs/delete
      (cond
        (not (seq graph-id))
        (http/bad-request "missing graph id")

        (not (string? user-id))
        (http/unauthorized)

        :else
        (p/let [owns? (index/<user-has-access-to-graph? db graph-id user-id)]
          (if (not owns?)
            (http/forbidden)
            (p/let [_ (<delete-graph! db env graph-id)]
              (http/json-response :graphs/delete {:graph-id graph-id :deleted true})))))

      :admin-graphs/delete
      (if (seq graph-id)
        (p/let [_ (<delete-graph! db env graph-id)]
          (http/json-response :graphs/delete {:graph-id graph-id :deleted true}))
        (http/bad-request "missing graph id"))

      (http/not-found))))

(defn handle-fetch [^js self request]
  (let [db (index-db self)
        env (.-env self)
        url (js/URL. (.-url request))
        path (.-pathname url)
        method (.-method request)]
    (try
      (cond
        (contains? #{"OPTIONS" "HEAD"} method)
        (common/options-response)

        (nil? db)
        (http/error-response "server error" 500)

        :else
        (let [route (routes/match-route method path)]
          (cond
            (nil? route)
            (http/not-found)

            (= :admin-graphs/delete (:handler route))
            (if (admin-token-valid? request env)
              (handle {:db db
                       :env env
                       :request request
                       :url url
                       :claims nil
                       :route route})
              (http/unauthorized))

            :else
            (p/let [claims (auth/auth-claims request env)
                    _ (when claims
                        (index/<user-upsert! db claims))]
              (if (nil? claims)
                (http/unauthorized)
                (p/let [user-id (aget claims "sub")
                        _ (<safe-user-activity-touch! db user-id)
                        response (handle {:db db
                                          :env env
                                          :request request
                                          :url url
                                          :claims claims
                                          :route route})
                        graph-id (some-> route :path-params :graph-id)
                        _ (when (and (string? user-id)
                                     (string? graph-id)
                                     (< (.-status response) 400))
                            (<safe-graph-activity-touch! db graph-id))]
                    response))))))
      (catch :default error
        (js/console.error "DEBUG handle-fetch error:" error)
        (log/error :db-sync/index-error error)
        (http/error-response (str "server error: " error) 500)))))

(def ^:private graph-access-cache-ttl-ms 5000)
(def ^:private graph-access-cache-capacity 256)
(defonce ^:private *graph-access-cache (atom {}))

(defn- now-ms []
  (.now js/Date))

(defn- unauthorized-timing [jwt-verify-ms]
  {:access-ok? false
   :cache-hit? false
   :jwt-verify-ms jwt-verify-ms
   :access-query-ms 0
   :access-check-ms jwt-verify-ms})

(defn- fresh-cache?
  [cached-at current-ms]
  (and (number? cached-at)
       (< (- current-ms cached-at) graph-access-cache-ttl-ms)))

(defn- lookup-graph-access-cache
  [graph-id token current-ms]
  (let [cache-key [graph-id token]]
    (when-let [{:keys [allowed? cached-at]} (get @*graph-access-cache cache-key)]
      (if (fresh-cache? cached-at current-ms)
        {:allowed? allowed?}
        (do
          (swap! *graph-access-cache dissoc cache-key)
          nil)))))

(defn- prune-graph-access-cache
  [cache current-ms]
  (let [fresh (into {}
                    (filter (fn [[_ {:keys [cached-at]}]]
                              (fresh-cache? cached-at current-ms)))
                    cache)]
    (if (<= (count fresh) graph-access-cache-capacity)
      fresh
      (let [drop-count (- (count fresh) graph-access-cache-capacity)]
        (->> fresh
             (sort-by (comp :cached-at val))
             (drop drop-count)
             (into {}))))))

(defn invalidate-graph-access!
  "Drops cached access decisions for `graph-id`, so a membership change is
  enforced on the next request instead of after the cache TTL."
  [graph-id]
  (swap! *graph-access-cache
         (fn [cache]
           (into {}
                 (remove (fn [[[cached-graph-id _] _]]
                           (= cached-graph-id graph-id)))
                 cache))))

(defn- cache-graph-access!
  [graph-id token allowed? current-ms]
  (let [cache-key [graph-id token]]
    (swap! *graph-access-cache
           (fn [cache]
             (-> cache
                 (assoc cache-key {:allowed? allowed? :cached-at current-ms})
                 (prune-graph-access-cache current-ms))))))

(defn graph-access-response-with-timing
  [request env graph-id]
  (let [token (auth/token-from-request request)
        db (aget env "DB")]
    (cond
      (or (not (string? token))
          (not (seq token)))
      (p/resolved {:response (http/unauthorized)
                   :timing (unauthorized-timing 0)})

      (nil? db)
      (p/resolved {:response (http/error-response "server error" 500)
                   :timing {:access-ok? false
                            :cache-hit? false}})

      :else
      (let [current-ms (now-ms)]
        (if-let [{:keys [allowed?]} (lookup-graph-access-cache graph-id token current-ms)]
          (p/resolved {:response (if allowed?
                                   (http/json-response :graphs/access {:ok true})
                                   (http/forbidden))
                       :timing {:access-ok? allowed?
                                :cache-hit? true
                                :jwt-verify-ms 0
                                :access-query-ms 0
                                :access-check-ms 0}})
          (let [jwt-start-ms (now-ms)]
            (->
             (p/let [claims (auth/auth-claims request env)
                     jwt-end-ms (now-ms)
                     jwt-verify-ms (- jwt-end-ms jwt-start-ms)]
               (if (nil? claims)
                 {:response (http/unauthorized)
                  :timing (unauthorized-timing jwt-verify-ms)}
                 (let [user-id (aget claims "sub")]
                   (if-not (string? user-id)
                     {:response (http/unauthorized)
                      :timing (unauthorized-timing jwt-verify-ms)}
                     (p/let [query-start-ms (now-ms)
                             access? (index/<user-has-access-to-graph? db graph-id user-id)
                             query-end-ms (now-ms)
                             access-query-ms (- query-end-ms query-start-ms)
                             access-check-ms (+ jwt-verify-ms access-query-ms)
                             _ (cache-graph-access! graph-id token (true? access?) query-end-ms)
                             response (if access?
                                        (http/json-response :graphs/access {:ok true})
                                        (http/forbidden))]
                       {:response response
                        :timing {:access-ok? (true? access?)
                                 :cache-hit? false
                                 :jwt-verify-ms jwt-verify-ms
                                 :access-query-ms access-query-ms
                                 :access-check-ms access-check-ms}})))))
             (p/catch (fn [error]
                        (log/error :db-sync/index-error error)
                        (p/resolved {:response (http/error-response (str "server error: " error) 500)
                                     :timing {:access-ok? false
                                              :cache-hit? false}}))))))))))

(defn graph-access-response [request env graph-id]
  (p/let [{:keys [response]} (graph-access-response-with-timing request env graph-id)]
    response))
