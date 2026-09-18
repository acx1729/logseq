(ns frontend.components.user.login
  "Sign-in through the wallet bundle: the identity this device holds, or any
   wallet RainbowKit connects."
  (:require [frontend.config :as config]
            [frontend.context.i18n :refer [t]]
            [frontend.handler.notification :as notification]
            [frontend.handler.route :as route-handler]
            [frontend.handler.user :as user]
            [frontend.modules.shortcut.core :as shortcut]
            [frontend.state :as state]
            [frontend.wallet :as wallet]
            [io.factorhouse.hsx.core :as hsx]
            [lambdaisland.glogi :as log]
            [logseq.shui.hooks :as hooks]
            [logseq.shui.ui :as shui]
            [promesa.core :as p]))

(defn- error-text
  [error]
  (or (some-> error .-message) (str error)))

(defn- finish-sign-in!
  [^js result]
  (user/login-with-token! (.-accessToken result))
  (shui/dialog-close!)
  (shui/popup-hide!)
  (when (= :user-login (state/get-current-route))
    (route-handler/redirect! {:to :home})))

(hsx/defc wallet-login
  []
  (let [container-ref (hooks/use-ref nil)
        [failure set-failure!] (hooks/use-state nil)]
    (hooks/use-effect!
     (fn []
       (let [*handle (atom nil)
             *cancelled (atom false)]
         (-> (wallet/<mount-login!
              (hooks/deref container-ref)
              {:on-signed-in (fn [result]
                               (try
                                 (finish-sign-in! result)
                                 (catch :default e
                                   (log/error :user/sign-in-failed {:error e})
                                   (notification/show! (t :wallet/sign-in-failed (error-text e)) :error))))
               :on-error (fn [error]
                           (log/warn :user/sign-in-error {:error error}))})
             (p/then (fn [^js handle]
                       (if @*cancelled
                         (.unmount handle)
                         (reset! *handle handle))))
             (p/catch (fn [error]
                        (log/error :wallet/load-failed {:error error})
                        (set-failure! (error-text error)))))
         (fn []
           (reset! *cancelled true)
           (when-let [^js handle @*handle]
             (.unmount handle)))))
     [])
    (if failure
      [shui/alert {:variant :destructive}
       [shui/alert-description (t :wallet/bundle-failed failure)]]
      [:div.ls-wallet-root {:ref container-ref}])))

(hsx/defc page-impl
  []
  (let [server-url (config/sync-server-url)]
    [:div.cp__user-login.flex.flex-col.gap-4
     (shui/card-header
      {:class "px-0" :data-auth-title-key "login"}
      (shui/card-title (t :ui/login)))
     (if server-url
       (wallet-login)
       [:div.flex.flex-col.gap-3
        [:p.text-sm.opacity-70 (t :wallet/server-required)]
        (shui/button
         {:on-click (fn []
                      (shui/dialog-close!)
                      (state/pub-event! [:go/sync-server-settings]))}
         (t :settings.sync-server/url))])]))

(hsx/defc dialog-inner
  []
  (shortcut/use-disable-all-shortcuts!)
  (page-impl))

(hsx/defc page
  []
  [:div.pt-10 (page-impl)])

(defn open-login-modal!
  []
  (shui/dialog-open!
   (fn [_close] (dialog-inner))
   {:label :user-login
    :class "lg:max-w-xl"
    ;; RainbowKit's own modal opens outside this dialog; clicks there must not close it.
    :content-props {:onPointerDownOutside #(.preventDefault %)
                    :onInteractOutside #(.preventDefault %)}}))
