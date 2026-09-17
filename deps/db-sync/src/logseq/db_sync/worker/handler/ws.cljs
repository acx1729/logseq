(ns logseq.db-sync.worker.handler.ws
  (:require [logseq.db-sync.protocol :as protocol]
            [logseq.db-sync.worker.handler.sync :as sync-handler]
            [logseq.db-sync.worker.presence :as presence]
            [logseq.db-sync.worker.ws :as ws]))

(defn handle-ws-message! [^js self ^js ws raw]
  (let [message (-> raw protocol/parse-message ws/coerce-ws-client-message)]
    (if-not (map? message)
      (ws/send! ws {:type "error" :message "invalid request"})
      (case (:type message)
        "hello"
        (let [checksum (sync-handler/current-checksum self)]
          (ws/send! ws (cond-> {:type "hello"
                                :t (sync-handler/t-now self)}
                         (string? checksum) (assoc :checksum checksum))))

        "ping"
        (ws/send! ws {:type "pong"})

        "presence"
        (let [editing-block-uuid (:editing-block-uuid message)
              user (presence/get-user self ws)]
          (presence/update-presence! self ws {:editing-block-uuid editing-block-uuid})
          (ws/broadcast! self ws {:type "presence"
                                  :editing-block-uuid editing-block-uuid
                                  :user-id (:user-id user)}))

        "pull"
        (let [raw-since (:since message)
              since (if (some? raw-since) (sync-handler/parse-int raw-since) 0)]
          (if (or (and (some? raw-since) (not (number? since))) (neg? since))
            (ws/send! ws {:type "error" :message "invalid since"})
            (ws/send! ws (sync-handler/pull-response self since))))

        "tx/batch"
        (let [txs (:txs message)
              user (presence/get-user self ws)
              t-before (sync-handler/parse-int (:t-before message))]
          (if (sequential? txs)
            (ws/send! ws (sync-handler/handle-tx-batch!
                          self
                          ws
                          txs
                          t-before
                          (cond-> {:graph-id (aget self "graph-id")}
                            (:client-revision message)
                            (assoc :client-revision (:client-revision message))
                            (:username user)
                            (assoc :username (:username user)))))
            (ws/send! ws {:type "tx/reject" :reason "invalid tx"})))

        (ws/send! ws {:type "error" :message "unknown type"})))))
