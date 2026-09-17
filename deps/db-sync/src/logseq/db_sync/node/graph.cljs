(ns logseq.db-sync.node.graph
  (:require [logseq.db-sync.node.storage :as storage]
            [logseq.db-sync.worker.presence :as presence]))

(defn- make-state []
  (let [sockets (atom #{})]
    #js {:getWebSockets (fn [] (to-array @sockets))
         :addWebSocket (fn [ws] (swap! sockets conj ws))
         :removeWebSocket (fn [ws] (swap! sockets disj ws))}))

(defn- env-object [index-db assets-bucket verify-token]
  (doto (js-obj)
    (aset "DB" index-db)
    (aset "LOGSEQ_SYNC_ASSETS" assets-bucket)
    ;; Keep node-adapter snapshot stream uncompressed.
    (aset "DB_SYNC_SNAPSHOT_STREAM_GZIP" "false")
    (aset "DB_SYNC_VERIFY_TOKEN" verify-token)))

(defn graph-context
  [{:keys [config index-db assets-bucket verify-token]} graph-id]
  (let [{:keys [sql]} (storage/open-graph-db (:data-dir config) graph-id)]
    #js {:state (make-state)
         :env (env-object index-db assets-bucket verify-token)
         :sql sql
         :conn nil
         :schema-ready false}))

(defn get-or-create-graph
  [registry deps graph-id]
  (or (get @registry graph-id)
      (let [ctx (graph-context deps graph-id)]
        (swap! registry assoc graph-id ctx)
        ctx)))

(defn- close-sockets!
  [^js ctx pred code reason]
  (let [^js state (.-state ctx)]
    (doseq [^js ws (.getWebSockets state)]
      (when (pred ws)
        (.close ws code reason)))))

(defn close-member-sockets!
  "Closes every socket `user-id` holds on `graph-id`, so a removed member
  stops reading and writing at once instead of when the connection drops."
  [registry graph-id user-id]
  (when-let [^js ctx (get @registry graph-id)]
    (close-sockets! ctx
                    (fn [ws] (= user-id (:user-id (presence/get-user ctx ws))))
                    4003
                    "access revoked")))

(defn- close-graph-context!
  [^js ctx code reason]
  (close-sockets! ctx (constantly true) code reason)
  (when-let [^js sql (.-sql ctx)]
    (when-let [close (.-close sql)]
      (close))))

(defn delete-graph!
  [registry deps graph-id]
  (when-let [^js ctx (get @registry graph-id)]
    (close-graph-context! ctx 1000 "graph deleted")
    (swap! registry dissoc graph-id))
  (storage/delete-graph-db! (get-in deps [:config :data-dir]) graph-id))

(defn close-graphs! [registry]
  (doseq [[_ ^js ctx] @registry]
    (close-graph-context! ctx 1001 "server shutdown")))
