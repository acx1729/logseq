(ns logseq.db-sync.worker.routes.index
  (:require [reitit.core :as r]))

(def ^:private route-data
  [["/admin"
    ["/graphs/:graph-id" {:methods {"DELETE" :admin-graphs/delete}}]]

   ["/graphs"
    ["" {:methods {"GET" :graphs/list
                   "POST" :graphs/create}}]
    ["/:graph-id"
     ["/access" {:methods {"GET" :graphs/access}}]
     ["/key" {:methods {"GET" :graphs/key}}]
     ["/members" {:methods {"GET" :graph-members/list
                            "POST" :graph-members/create}}]
     ["/members/:member-id" {:methods {"PUT" :graph-members/update
                                       "DELETE" :graph-members/delete}}]
     ["" {:methods {"DELETE" :graphs/delete}}]]]])

(def ^:private router
  (r/router route-data))

(defn match-route [method path]
  (when-let [match (r/match-by-path router path)]
    (when-let [handler (get-in match [:data :methods method])]
      (assoc match :handler handler))))
