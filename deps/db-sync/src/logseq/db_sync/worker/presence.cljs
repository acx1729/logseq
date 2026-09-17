(ns logseq.db-sync.worker.presence
  (:require [clojure.string :as string]
            [logseq.db-sync.worker.ws :as ws]))

(defn claims->user
  [claims]
  (when claims
    (let [user-id (aget claims "sub")
          username (aget claims "username")]
      (when (string? user-id)
        (cond-> {:user-id user-id}
          (string? username) (assoc :username username))))))

(defn presence*
  [^js self]
  (or (.-presence self)
      (set! (.-presence self) (atom {}))))

(defn online-users
  [^js self]
  (vec (distinct (vals @(presence* self)))))

(defn broadcast-online-users!
  [^js self]
  (ws/broadcast! self nil {:type "online-users" :online-users (online-users self)}))

(defn add-presence!
  [^js self ^js ws user]
  (swap! (presence* self) assoc ws user))

(defn update-presence!
  [^js self ^js ws {:keys [editing-block-uuid] :as updates}]
  (swap! (presence* self)
         (fn [presence]
           (if-let [user (get presence ws)]
             (assoc presence ws
                    (if (contains? updates :editing-block-uuid)
                      (if (and (string? editing-block-uuid)
                               (not (string/blank? editing-block-uuid)))
                        (assoc user :editing-block-uuid editing-block-uuid)
                        (dissoc user :editing-block-uuid))
                      user))
             presence))))

(defn get-user
  [^js self ^js ws]
  (get @(presence* self) ws))

(defn remove-presence!
  [^js self ^js ws]
  (swap! (presence* self) dissoc ws))
