(ns logseq.db-sync.index-test
  (:require [cljs.test :refer [async deftest is]]
            [clojure.string :as string]
            [logseq.db-sync.common :as common]
            [logseq.db-sync.index :as index]
            [promesa.core :as p]))

(def ^:private graph-members-graph-id-created-at-index-sql
  "create index if not exists idx_graph_members_graph_id_created_at on graph_members (graph_id, created_at)")
(def ^:private graphs-user-id-updated-at-index-sql
  "create index if not exists idx_graphs_user_id_updated_at on graphs (user_id, updated_at desc)")
(def ^:private users-email-index-sql
  "create index if not exists idx_users_email on users (email)")

(deftest index-list-includes-graph-e2ee-flag-test
  (async done
         (let [rows #js [#js {"graph_id" "graph-1"
                              "graph_name" "Graph 1"
                              "schema_version" "65"
                              "role" "manager"
                              "invited_by" nil
                              "created_at" 10
                              "updated_at" 20
                              "graph_e2ee" 0}
                         #js {"graph_id" "graph-2"
                              "graph_name" "Graph 2"
                              "schema_version" "65"
                              "role" "member"
                              "invited_by" "u1"
                              "created_at" 11
                              "updated_at" 21
                              "graph_e2ee" 1
                              "graph_ready_for_use" 0}]]
           (-> (p/with-redefs [common/<d1-all (fn [& _]
                                                (p/resolved #js {:results rows}))
                               common/get-sql-rows (fn [result]
                                                     (aget result "results"))]
                 (index/<index-list :db "user-1"))
               (p/then (fn [graphs]
                         (is (= 2 (count graphs)))
                         (is (= false (:graph-e2ee? (first graphs))))
                         (is (= true (:graph-e2ee? (second graphs))))
                         (is (= true (:graph-ready-for-use? (first graphs))))
                         (is (= false (:graph-ready-for-use? (second graphs))))
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest semantic-graphs-list-is-bounded-and-excludes-e2ee-test
  (async done
         (let [call (atom nil)
               rows #js [#js {"graph_id" "graph-1" "graph_name" "test-mcp"
                              "updated_at" 20 "created_at" 10 "schema_version" "65"
                              "graph_ready_for_use" 1 "role" "manager" "invited_by" nil}
                         #js {"graph_id" "graph-2" "graph_name" "test-mcp-2"
                              "updated_at" 19 "created_at" 11 "schema_version" "65"
                              "graph_ready_for_use" 1 "role" "member" "invited_by" "u2"}]]
           (-> (p/with-redefs [common/<d1-all
                               (fn [_db sql & args]
                                 (reset! call {:sql sql :args args})
                                 (p/resolved #js {:results rows}))
                               common/get-sql-rows (fn [result] (aget result "results"))]
                 (index/<semantic-graphs-list :db "user-1" {:name "test-mcp" :limit 1 :cursor nil}))
               (p/then (fn [{:keys [graphs next-cursor]}]
                         (is (= 1 (count graphs)))
                         (is (string? next-cursor))
                         (is (string/includes? (:sql @call) "g.graph_e2ee = 0"))
                         (is (string/includes? (:sql @call) "limit ?"))
                         (is (= 2 (last (:args @call))))
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest index-upsert-persists-graph-e2ee-flag-test
  (async done
         (let [called (atom nil)]
           (-> (p/with-redefs [common/now-ms (fn [] 1234)
                               common/<d1-run (fn [_db sql & args]
                                                (reset! called {:sql sql
                                                                :args args})
                                                (p/resolved {:ok true}))]
                 (index/<index-upsert! :db "graph-1" "Graph 1" "user-1" "65" false))
               (p/then (fn [_]
                         (is (string/includes? (:sql @called) "graph_e2ee"))
                         (is (= ["graph-1" "Graph 1" "user-1" "65" 0 1 1234 1234]
                                (:args @called)))
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(deftest index-upsert-persists-graph-ready-for-use-flag-test
  (async done
         (let [called (atom nil)]
           (-> (p/with-redefs [common/now-ms (fn [] 1234)
                               common/<d1-run (fn [_db sql & args]
                                                (reset! called {:sql sql
                                                                :args args})
                                                (p/resolved {:ok true}))]
                 (index/<index-upsert! :db "graph-1" "Graph 1" "user-1" "65" false false))
               (p/then (fn [_]
                         (is (string/includes? (:sql @called) "graph_ready_for_use"))
                         (is (= ["graph-1" "Graph 1" "user-1" "65" 0 0 1234 1234]
                                (:args @called)))
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))

(defn- run-index-init!
  "Runs <index-init! against fakes; `applied` lists the migration ids the
  fake schema_migrations table already holds. Returns the recorded statements."
  [applied extra-migrations]
  (let [sql-calls (atom [])]
    (-> (p/with-redefs [common/<d1-all (fn [_db sql & _args]
                                         (p/resolved
                                          (if (string/includes? sql "schema_migrations")
                                            #js {:results (into-array (map (fn [id] #js {"id" id}) applied))}
                                            #js {:results #js []})))
                        common/get-sql-rows (fn [result]
                                              (aget result "results"))
                        common/<d1-run (fn [_db sql & args]
                                         (swap! sql-calls conj {:sql (string/lower-case sql)
                                                                :args args})
                                         (p/resolved {:ok true}))]
          (index/<index-init! :db extra-migrations))
        (p/then (fn [_] @sql-calls)))))

(defn- migration-inserts [sql-calls]
  (->> sql-calls
       (filter #(string/includes? (:sql %) "insert into schema_migrations"))
       (map (comp first :args))))

(deftest index-init-applies-base-migration-once-test
  (async done
         (-> (p/let [first-run (run-index-init! [] [])
                     second-run (run-index-init! ["0001-index-baseline"] [])]
               (is (some #(string/includes? (:sql %) "create table if not exists schema_migrations") first-run))
               (is (some #(string/includes? (:sql %) "create table if not exists graphs") first-run))
               (is (some #(string/includes? (:sql %) "create table if not exists graph_members") first-run))
               (is (= ["0001-index-baseline"] (migration-inserts first-run)))
               (is (not-any? #(string/includes? (:sql %) "create table if not exists graphs") second-run))
               (is (empty? (migration-inserts second-run))))
             (p/then (fn [] (done)))
             (p/catch (fn [error]
                        (is false (str error))
                        (done))))))

(deftest index-init-applies-extra-migrations-after-base-test
  (async done
         (-> (p/let [extra [{:id "0002-auth-tables"
                             :statements ["create table if not exists auth_nonces (nonce TEXT primary key)"]}]
                     sql-calls (run-index-init! [] extra)]
               (is (some #(string/includes? (:sql %) "create table if not exists auth_nonces") sql-calls))
               (is (= ["0001-index-baseline" "0002-auth-tables"] (migration-inserts sql-calls))))
             (p/then (fn [] (done)))
             (p/catch (fn [error]
                        (is false (str error))
                        (done))))))

(deftest index-migrations-use-portable-ddl-test
  (doseq [{:keys [id statements]} index/index-migrations]
    (is (re-matches #"\d{4}-[a-z-]+" id))
    (doseq [statement statements]
      (is (not (re-find #"(?i)autoincrement|json_each|pragma|insert or replace" statement))
          (str id ": " statement)))))

(deftest index-init-creates-indexes-test
  (async done
         (let [sql-calls (atom [])]
           (-> (p/with-redefs [common/<d1-all (fn [& _]
                                                (p/resolved #js {:results #js []}))
                               common/get-sql-rows (fn [result]
                                                     (aget result "results"))
                               common/<d1-run (fn [_db sql & _args]
                                                (swap! sql-calls conj (string/lower-case sql))
                                                (p/resolved {:ok true}))]
                 (index/<index-init! :db))
               (p/then (fn [_]
                         (is (some #(string/includes? % graph-members-graph-id-created-at-index-sql)
                                   @sql-calls))
                         (is (some #(string/includes? % graphs-user-id-updated-at-index-sql)
                                   @sql-calls))
                         (is (some #(string/includes? % users-email-index-sql)
                                   @sql-calls))
                         (done)))
               (p/catch (fn [error]
                          (is false (str error))
                          (done)))))))
