(ns frontend.worker.sync.crypt
  "Graph encryption on the worker. Every synced graph has one AES-256 key that
  the sync server custodies; members fetch it once per session over the key
  route and hold it in memory only. Block titles and names, snapshot rows and
  assets are encrypted with it before they leave the device."
  (:require [frontend.common.crypt :as crypt]
            [frontend.worker.state :as worker-state]
            [frontend.worker.sync.auth :as sync-auth]
            [frontend.worker.sync.const :as sync-const]
            [frontend.worker.sync.util :refer [fail-fast fetch-json]]
            [logseq.db :as ldb]
            [promesa.core :as p]))

(defonce ^:private *graph->aes-key (atom {}))
(defonce ^:private *graph->aes-key-inflight (atom {}))
(def ^:private invalid-transit ::invalid-transit)
(def ^:private aes-key-bytes 32)

(defn- read-transit-safe
  [value]
  (try
    (ldb/read-transit-str value)
    (catch :default _
      invalid-transit)))

(defn- base64->bytes
  [text]
  (let [binary (js/atob text)
        bytes (js/Uint8Array. (.-length binary))]
    (dotimes [i (.-length binary)]
      (aset bytes i (.charCodeAt binary i)))
    bytes))

(defn- <fetch-graph-key
  "GET /graphs/:graph-id/key on the sync server; members only. Every failure
  is a rejection, including a missing server address."
  [graph-id]
  (p/let [base (sync-auth/http-base-url @worker-state/*db-sync-config)
          _ (when-not (seq base)
              (fail-fast :db-sync/missing-field {:graph-id graph-id :field :http-base}))
          resp (fetch-json (str base "/graphs/" graph-id "/key")
                           {:method "GET"}
                           {:response-schema :graphs/key})
          key-bytes (base64->bytes (:key resp))]
    (when-not (= aes-key-bytes (.-length key-bytes))
      (fail-fast :db-sync/invalid-field {:graph-id graph-id :field :key}))
    (crypt/<import-aes-key key-bytes)))

(defn <ensure-graph-aes-key
  "The graph's key as a CryptoKey, fetched from the sync server the first time
  it is needed in this session and cached in memory. Concurrent callers share
  one request."
  [graph-id]
  (when-not (string? graph-id)
    (fail-fast :db-sync/missing-field {:graph-id graph-id :field :graph-id}))
  (if-let [cached (get @*graph->aes-key graph-id)]
    (p/resolved cached)
    (if-let [inflight (get @*graph->aes-key-inflight graph-id)]
      inflight
      (let [request (-> (<fetch-graph-key graph-id)
                        (p/then (fn [aes-key]
                                  (swap! *graph->aes-key assoc graph-id aes-key)
                                  aes-key))
                        (p/finally (fn [& _]
                                     (swap! *graph->aes-key-inflight dissoc graph-id))))]
        (swap! *graph->aes-key-inflight assoc graph-id request)
        request))))

(defn forget-graph-aes-keys!
  "Drops every cached key, for tests and for sign-out."
  []
  (reset! *graph->aes-key {})
  (reset! *graph->aes-key-inflight {}))

(defn <encrypt-text-value
  [aes-key value]
  (assert (string? value) (str "encrypting value should be a string, value: " value))
  (p/let [encrypted (crypt/<encrypt-text aes-key (ldb/write-transit-str value))]
    (ldb/write-transit-str encrypted)))

(defn <decrypt-text-value
  [aes-key value]
  (assert (string? value) (str "encrypted value should be a string, value: " value))
  (let [decoded (read-transit-safe value)]
    (if (= decoded invalid-transit)
      (p/resolved value)
      (p/let [value (or (crypt/<decrypt-text-if-encrypted aes-key decoded)
                        decoded)
              value' (if (string? value)
                       (read-transit-safe value)
                       value)]
        (if (= value' invalid-transit)
          value
          value')))))

(defn- encrypt-tx-item
  [aes-key item]
  (cond
    (and (vector? item) (<= 4 (count item)))
    (let [attr (nth item 2)
          v (nth item 3)]
      (if (contains? sync-const/encrypt-attr-set attr)
        (p/let [v' (<encrypt-text-value aes-key v)]
          (assoc item 3 v'))
        (p/resolved item)))

    :else
    (p/resolved item)))

(defn- decrypt-tx-item
  [aes-key item]
  (cond
    (and (vector? item) (<= 4 (count item)))
    (let [attr (nth item 2)
          v (nth item 3)]
      (if (contains? sync-const/encrypt-attr-set attr)
        (p/let [v' (<decrypt-text-value aes-key v)]
          (assoc item 3 v'))
        (p/resolved item)))

    :else
    (p/resolved item)))

(defn <encrypt-tx-data
  [aes-key tx-data]
  (p/let [items (p/all (mapv (fn [item] (encrypt-tx-item aes-key item)) tx-data))]
    items))

(defn <decrypt-tx-data
  [aes-key tx-data]
  (p/let [items (p/all (mapv (fn [item] (decrypt-tx-item aes-key item)) tx-data))]
    items))

(defn- <decrypt-datoms
  [aes-key data]
  (p/all
   (map
    (fn [[e a v t]]
      (if (contains? sync-const/encrypt-attr-set a)
        (p/let [v' (<decrypt-text-value aes-key v)]
          [e a v' t])
        [e a v t]))
    data)))

(defn- <decrypt-snapshot-row
  [aes-key row]
  (let [[addr raw-content raw-addresses] row
        data (ldb/read-transit-str raw-content)
        addresses (when raw-addresses
                    (js/JSON.parse raw-addresses))]
    (if (map? data)
      (p/let [keys (:keys data)
              keys' (if (seq keys)
                      (<decrypt-datoms aes-key (:keys data))
                      keys)
              result (assoc data :keys keys')]
        [addr (ldb/write-transit-str (cond-> result
                                       (some? addresses)
                                       (assoc :addresses addresses)))
         raw-addresses])
      (p/let [result (p/all (map #(<decrypt-datoms aes-key %) data))]
        [addr (ldb/write-transit-str result) raw-addresses]))))

(defn <decrypt-snapshot-rows-batch
  [aes-key rows-batch]
  (p/all (map #(<decrypt-snapshot-row aes-key %) rows-batch)))

(defn <decrypt-snapshot-datoms-batch
  [aes-key datoms]
  (p/all
   (map (fn [{:keys [a v] :as datom}]
          (if (contains? sync-const/encrypt-attr-set a)
            (p/let [v' (<decrypt-text-value aes-key v)]
              (assoc datom :v v'))
            (p/resolved datom)))
        datoms)))

(defn <encrypt-datoms
  ([aes-key datoms]
   (<encrypt-datoms aes-key datoms nil))
  ([aes-key datoms progress-f]
   (let [batch-size 5000
         total-count (count datoms)
         batches (partition-all batch-size datoms)]
     (p/loop [remaining batches
              result []
              encrypted-count 0]
       (if (empty? remaining)
         result
         (p/let [batch (first remaining)
                 encrypted (p/all (map (fn [datom]
                                         (if (contains? sync-const/encrypt-attr-set (:a datom))
                                           (p/let [v' (<encrypt-text-value aes-key (:v datom))]
                                             (assoc datom :v v'))
                                           (p/resolved datom)))
                                       batch))]
           (let [encrypted-count' (+ encrypted-count (count batch))]
             (when progress-f
               (progress-f encrypted-count' total-count))
             (p/recur (rest remaining) (into result encrypted) encrypted-count'))))))))
