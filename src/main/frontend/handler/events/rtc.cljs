(ns frontend.handler.events.rtc
  "RTC events"
  (:require-macros [frontend.handler.events.macros :refer [defevent!]])
  (:require [frontend.context.i18n :refer [t]]
            [frontend.flows :as flows]
            [frontend.handler.events :as events]
            [frontend.handler.notification :as notification]
            [frontend.state :as state]
            [promesa.core :as p]))

(defevent! :rtc/storage-exceed-limit [[_]]
  (notification/show! (t :sync/storage-exceed-limit) :warning false))

(defevent! :rtc/graph-count-exceed-limit [[_]]
  (notification/show! (t :sync/graph-count-exceed-limit) :warning false))

(defonce ^:private *sync-app-state-cancel! (atom nil))

(defn- sync-app-state!
  []
  (when-let [cancel! @*sync-app-state-cancel!]
    (cancel!))
  (let [state-atoms {:git/current-repo flows/current-repo
                     :config (flows/sub-atom [:config])
                     :auth/access-token (flows/sub-atom [:auth/access-token])}
        <init-sync-done? (p/deferred)
        last-state (atom ::not-set)
        app-state (fn [] (update-vals state-atoms deref))
        sync! (fn []
                (let [m (app-state)]
                  (when-not (= @last-state m)
                    (reset! last-state m)
                    (p/let [_ (when (:git/current-repo m)
                                (state/<invoke-db-worker :thread-api/sync-app-state m))]
                      (p/resolve! <init-sync-done?)))))]
    (doseq [[k atom'] state-atoms]
      (add-watch atom' [::sync-app-state k] (fn [_ _ _ _] (sync!))))
    (sync!)
    (reset! *sync-app-state-cancel!
            (fn []
              (doseq [[k atom'] state-atoms]
                (remove-watch atom' [::sync-app-state k]))))
    <init-sync-done?))

(defevent! :rtc/sync-app-state [[_]]
  (sync-app-state!))
