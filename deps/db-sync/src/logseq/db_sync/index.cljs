(ns logseq.db-sync.index
  (:require [clojure.string :as string]
            [logseq.db-sync.common :as common]
            [promesa.core :as p]))

(def ^:private activity-touch-cache-max 8192)
(defonce ^:private *activity-touch-cache (atom {}))

(defn- graph-e2ee-sql->bool
  [v]
  (cond
    (nil? v) true
    (or (= 1 v) (= "1" v)) true
    (or (= 0 v) (= "0" v)) false
    :else (true? v)))

(defn- graph-ready-for-use-sql->bool
  [v]
  (cond
    (nil? v) true
    (or (= 1 v) (= "1" v)) true
    (or (= 0 v) (= "0" v)) false
    :else (true? v)))

(defn- graph-ready-for-use-bool->sql
  [v]
  (if (false? v) 0 1))

(def ^:private daily-active-entities-create-table-sql
  (str "create table if not exists daily_active_entities ("
       "day_utc TEXT,"
       "entity_type TEXT,"
       "entity_id TEXT,"
       "first_seen_at INTEGER,"
       "primary key (day_utc, entity_type, entity_id),"
       "check (entity_type in ('user', 'graph'))"
       ");"))
(def ^:private daily-active-entities-create-index-sql
  "create index if not exists idx_daily_active_entities_type_day on daily_active_entities (entity_type, day_utc)")

(def ^:private schema-migrations-table-sql
  (str "create table if not exists schema_migrations ("
       "id TEXT primary key,"
       "applied_at INTEGER not null"
       ");"))

(def index-migrations
  "Index database schema, applied in order and recorded in `schema_migrations`.
  Every schema change is a new entry; DDL stays portable across SQLite and
  Postgres (no pragma probes, no autoincrement, no `insert or replace`)."
  [{:id "0001-index-baseline"
    :statements
    [(str "create table if not exists graphs ("
          "graph_id TEXT primary key,"
          "graph_name TEXT,"
          "user_id TEXT,"
          "schema_version TEXT,"
          "graph_e2ee INTEGER DEFAULT 1,"
          "graph_ready_for_use INTEGER DEFAULT 1,"
          "created_at INTEGER,"
          "updated_at INTEGER"
          ");")
     (str "create table if not exists users ("
          "id TEXT primary key,"
          "email TEXT,"
          "email_verified INTEGER,"
          "username TEXT,"
          "created_at INTEGER"
          ");")
     (str "create table if not exists user_rsa_keys ("
          "user_id TEXT primary key,"
          "public_key TEXT,"
          "encrypted_private_key TEXT,"
          "created_at INTEGER,"
          "updated_at INTEGER"
          ");")
     (str "create table if not exists graph_members ("
          "user_id TEXT,"
          "graph_id TEXT,"
          "role TEXT,"
          "invited_by TEXT,"
          "created_at INTEGER,"
          "primary key (user_id, graph_id),"
          "check (role in ('manager', 'member'))"
          ");")
     (str "create table if not exists graph_aes_keys ("
          "graph_id TEXT,"
          "user_id TEXT,"
          "encrypted_aes_key TEXT,"
          "created_at INTEGER,"
          "updated_at INTEGER,"
          "primary key (graph_id, user_id)"
          ");")
     daily-active-entities-create-table-sql
     "create index if not exists idx_graph_members_graph_id_created_at on graph_members (graph_id, created_at)"
     "create index if not exists idx_graphs_user_id_updated_at on graphs (user_id, updated_at desc)"
     "create index if not exists idx_users_email on users (email)"
     daily-active-entities-create-index-sql]}
   {:id "0003-drop-key-tables"
    :statements
    ["drop table if exists user_rsa_keys"
     "drop table if exists graph_aes_keys"]}
   {:id "0005-drop-user-email"
    :statements
    ["drop index if exists idx_users_email"
     "alter table users drop column email_verified"
     "alter table users drop column email"]}])

(defn- <run-statements! [db statements]
  (reduce (fn [acc statement]
            (p/then acc (fn [_] (common/<d1-run db statement))))
          (p/resolved nil)
          statements))

(defn- <applied-migration-ids [db]
  (p/let [result (common/<d1-all db "select id from schema_migrations")
          rows (common/get-sql-rows result)]
    (set (map (fn [row] (aget row "id")) rows))))

(defn <apply-migrations!
  "Applies, in id order, every migration whose id is not yet recorded."
  [db migrations]
  (p/let [_ (common/<d1-run db schema-migrations-table-sql)
          applied (<applied-migration-ids db)]
    (reduce (fn [acc {:keys [id statements]}]
              (p/then acc
                      (fn [_]
                        (when-not (contains? applied id)
                          (p/let [_ (<run-statements! db statements)]
                            (common/<d1-run db
                                            "insert into schema_migrations (id, applied_at) values (?, ?)"
                                            id
                                            (common/now-ms)))))))
            (p/resolved nil)
            (sort-by :id migrations))))

(defn <index-init!
  "Bootstraps the index database: the base migrations and the ones the adapter
  contributes (the auth tables), each applied once in id order, so a
  migration's numeric prefix is its position."
  ([db] (<index-init! db []))
  ([db extra-migrations]
   (<apply-migrations! db (concat index-migrations extra-migrations))))

(defn- utc-day-str
  [timestamp-ms]
  (-> (.toISOString (js/Date. timestamp-ms))
      (subs 0 10)))

(defn- prune-activity-touch-cache!
  [cache]
  (if (<= (count cache) activity-touch-cache-max)
    cache
    (let [drop-count (- (count cache) activity-touch-cache-max)]
      (->> cache
           (sort-by val)
           (drop drop-count)
           (into {})))))

(defn- cache-activity-touch!
  [cache-key now-ms]
  (swap! *activity-touch-cache
         (fn [cache]
           (-> cache
               (assoc cache-key now-ms)
               (prune-activity-touch-cache!)))))

(defn- activity-touch-cached?
  [cache-key]
  (contains? @*activity-touch-cache cache-key))

(defn- <activity-touch!
  [db entity-type entity-id]
  (if (and (string? entity-id) (contains? #{"user" "graph"} entity-type))
    (let [now (common/now-ms)
          day-utc (utc-day-str now)
          cache-key [day-utc entity-type entity-id]]
      (if (activity-touch-cached? cache-key)
        (p/resolved nil)
        (p/let [_ (common/<d1-run db
                                  (str "insert into daily_active_entities (day_utc, entity_type, entity_id, first_seen_at) "
                                       "values (?, ?, ?, ?) "
                                       "on conflict(day_utc, entity_type, entity_id) do nothing")
                                  day-utc
                                  entity-type
                                  entity-id
                                  now)]
          (cache-activity-touch! cache-key now)
          nil)))
    (p/resolved nil)))

(defn <user-activity-touch!
  [db user-id]
  (<activity-touch! db "user" user-id))

(defn <graph-activity-touch!
  [db graph-id]
  (<activity-touch! db "graph" graph-id))

(defn <index-list [db user-id]
  (if (string? user-id)
    (p/let [result (common/<d1-all db
                                   (str "select g.graph_id, g.graph_name, g.schema_version, g.graph_e2ee, g.graph_ready_for_use, g.created_at, g.updated_at, "
                                        "m.role, m.invited_by "
                                        "from graphs g "
                                        "left join graph_members m on g.graph_id = m.graph_id and m.user_id = ? "
                                        "where g.user_id = ? or m.user_id = ? "
                                        "order by g.updated_at desc")
                                   user-id
                                   user-id
                                   user-id)
            rows (common/get-sql-rows result)]
      (mapv (fn [row]
              {:graph-id (aget row "graph_id")
               :graph-name (aget row "graph_name")
               :schema-version (aget row "schema_version")
               :graph-e2ee? (graph-e2ee-sql->bool (aget row "graph_e2ee"))
               :graph-ready-for-use? (graph-ready-for-use-sql->bool (aget row "graph_ready_for_use"))
               :role (aget row "role")
               :invited-by (aget row "invited_by")
               :created-at (aget row "created_at")
               :updated-at (aget row "updated_at")})
            rows))
    []))

(defn decode-semantic-graph-cursor [cursor]
  (when (string? cursor)
    (try
      (let [value (js->clj (js/JSON.parse (js/atob cursor)))]
        (when (and (vector? value)
                   (= 2 (count value))
                   (number? (first value))
                   (string? (second value)))
          value))
      (catch :default _
        nil))))

(defn- encode-semantic-graph-cursor [updated-at graph-id]
  (js/btoa (js/JSON.stringify (clj->js [updated-at graph-id]))))

(defn <semantic-graphs-list
  [db user-id {:keys [name limit cursor]}]
  (let [cursor-key (when cursor (decode-semantic-graph-cursor cursor))
        [cursor-updated-at cursor-graph-id] cursor-key
        conditions (cond-> [(str "(g.user_id = ? or m.user_id = ?) ")
                            "g.graph_e2ee = 0"
                            "g.graph_ready_for_use = 1"]
                     (string? name) (conj "lower(g.graph_name) = lower(?)")
                     cursor-key (conj "(g.updated_at < ? or (g.updated_at = ? and g.graph_id > ?))"))
        args (cond-> [user-id user-id user-id]
               (string? name) (conj name)
               cursor-key (conj cursor-updated-at cursor-updated-at cursor-graph-id)
               true (conj (inc limit)))
        sql (str "select g.graph_id, g.graph_name, g.schema_version, g.graph_ready_for_use, "
                 "g.created_at, g.updated_at, m.role, m.invited_by "
                 "from graphs g "
                 "left join graph_members m on g.graph_id = m.graph_id and m.user_id = ? "
                 "where " (string/join " and " conditions) " "
                 "order by g.updated_at desc, g.graph_id asc limit ?")]
    (p/let [result (apply common/<d1-all db sql args)
            rows (vec (common/get-sql-rows result))
            more? (> (count rows) limit)
            selected (take limit rows)
            graphs (mapv (fn [row]
                           {:graph-id (aget row "graph_id")
                            :graph-name (aget row "graph_name")
                            :schema-version (aget row "schema_version")
                            :graph-e2ee? false
                            :graph-ready-for-use? (graph-ready-for-use-sql->bool (aget row "graph_ready_for_use"))
                            :role (aget row "role")
                            :invited-by (aget row "invited_by")
                            :created-at (aget row "created_at")
                            :updated-at (aget row "updated_at")})
                         selected)]
      (cond-> {:graphs graphs}
        more? (assoc :next-cursor
                     (let [row (nth rows (dec limit))]
                       (encode-semantic-graph-cursor (aget row "updated_at")
                                                     (aget row "graph_id"))))))))

(defn <index-upsert!
  "Creates or updates a graph row. Every graph is encrypted with its own key,
  so `graph_e2ee` is always 1."
  [db graph-id graph-name user-id schema-version graph-ready-for-use?]
  (p/let [now (common/now-ms)
          graph-ready-for-use? (graph-ready-for-use-bool->sql graph-ready-for-use?)
          result (common/<d1-run db
                                 (str "insert into graphs (graph_id, graph_name, user_id, schema_version, graph_e2ee, graph_ready_for_use, created_at, updated_at) "
                                      "values (?, ?, ?, ?, ?, ?, ?, ?) "
                                      "on conflict(graph_id) do update set "
                                      "graph_name = excluded.graph_name, "
                                      "user_id = excluded.user_id, "
                                      "schema_version = excluded.schema_version, "
                                      "graph_e2ee = excluded.graph_e2ee, "
                                      "graph_ready_for_use = excluded.graph_ready_for_use, "
                                      "updated_at = excluded.updated_at")
                                 graph-id
                                 graph-name
                                 user-id
                                 schema-version
                                 1
                                 graph-ready-for-use?
                                 now
                                 now)]
    result))

(defn <graph-ready-for-use?
  [db graph-id]
  (when (string? graph-id)
    (p/let [result (common/<d1-all db
                                   "select graph_ready_for_use from graphs where graph_id = ?"
                                   graph-id)
            rows (common/get-sql-rows result)
            row (first rows)]
      (graph-ready-for-use-sql->bool (some-> row (aget "graph_ready_for_use"))))))

(defn <graph-ready-for-use-set!
  [db graph-id graph-ready-for-use?]
  (when (string? graph-id)
    (common/<d1-run db
                    "update graphs set graph_ready_for_use = ?, updated_at = ? where graph_id = ?"
                    (graph-ready-for-use-bool->sql graph-ready-for-use?)
                    (common/now-ms)
                    graph-id)))

(defn <graph-delete-metadata! [db graph-id]
  (common/<d1-run db "delete from graph_members where graph_id = ?" graph-id))

(defn <graph-delete-index-entry! [db graph-id]
  (common/<d1-run db "delete from graphs where graph_id = ?" graph-id))

(defn <graph-name-exists?
  [db graph-name user-id]
  (when (and (string? graph-name) (string? user-id))
    (p/let [result (common/<d1-all db
                                   "select graph_id from graphs where graph_name = ? and user_id = ?"
                                   graph-name
                                   user-id)
            rows (common/get-sql-rows result)]
      (boolean (seq rows)))))

(defn <user-sign-in!
  "Records a sign-in: creates the user's row named `default-username` when the
  address is new, stores `username` when the sign-in carried one, and
  resolves to the display name on file."
  [db user-id username default-username]
  (p/let [_ (common/<d1-run db
                            (str "insert into users (id, username, created_at) values (?, ?, ?) "
                                 "on conflict(id) do update set "
                                 "username = coalesce(?, users.username)")
                            user-id
                            (or username default-username)
                            (common/now-ms)
                            username)
          result (common/<d1-all db {:session "first-primary"}
                                 "select username from users where id = ?"
                                 user-id)
          row (first (common/get-sql-rows result))]
    (when-not row
      (throw (ex-info "user row missing after sign-in" {:user-id user-id})))
    (aget row "username")))

(defn <graph-member-upsert! [db graph-id user-id role invited-by]
  (let [now (common/now-ms)]
    (common/<d1-run db
                    (str "insert into graph_members (user_id, graph_id, role, invited_by, created_at) "
                         "values (?, ?, ?, ?, ?) "
                         "on conflict(user_id, graph_id) do update set "
                         "role = excluded.role, "
                         "invited_by = excluded.invited_by")
                    user-id
                    graph-id
                    role
                    invited-by
                    now)))

(defn <graph-members-list [db graph-id]
  (p/let [result (common/<d1-all db {:session "first-primary"}
                                 (str "select m.user_id, m.graph_id, m.role, m.invited_by, m.created_at, "
                                      "u.username "
                                      "from graph_members m "
                                      "left join users u on m.user_id = u.id "
                                      "where m.graph_id = ? order by m.created_at asc")
                                 graph-id)
          rows (common/get-sql-rows result)]
    (mapv (fn [row]
            {:user-id (aget row "user_id")
             :graph-id (aget row "graph_id")
             :role (aget row "role")
             :invited-by (aget row "invited_by")
             :created-at (aget row "created_at")
             :username (aget row "username")})
          rows)))

(defn <graph-member-update-role! [db graph-id user-id role]
  (common/<d1-run db
                  (str "update graph_members set role = ? "
                       "where graph_id = ? and user_id = ?")
                  role
                  graph-id
                  user-id))

(defn <graph-member-delete! [db graph-id user-id]
  (common/<d1-run db
                  "delete from graph_members where graph_id = ? and user_id = ?"
                  graph-id
                  user-id))

(defn <graph-member-role [db graph-id user-id]
  (when (and (string? graph-id) (string? user-id))
    (p/let [result (common/<d1-all db
                                   "select role from graph_members where graph_id = ? and user_id = ?"
                                   graph-id
                                   user-id)
            rows (common/get-sql-rows result)
            row (first rows)]
      (when row
        (aget row "role")))))

(defn <user-has-access-to-graph? [db graph-id user-id]
  (when (and (string? graph-id) (string? user-id))
    (p/let [result (common/<d1-all db
                                   (str "select graph_id from graphs where graph_id = ? and user_id = ? "
                                        "union select graph_id from graph_members where graph_id = ? and user_id = ?")
                                   graph-id
                                   user-id
                                   graph-id
                                   user-id)
            rows (common/get-sql-rows result)]
      (boolean (seq rows)))))

(defn <user-is-manager? [db graph-id user-id]
  (when (and (string? graph-id) (string? user-id))
    (p/let [result (common/<d1-all db
                                   (str "select graph_id from graphs where graph_id = ? and user_id = ? "
                                        "union select graph_id from graph_members where graph_id = ? and user_id = ? and role = 'manager'")
                                   graph-id
                                   user-id
                                   graph-id
                                   user-id)
            rows (common/get-sql-rows result)]
      (boolean (seq rows)))))
