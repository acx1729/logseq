(ns frontend.handler.user-test
  (:require [cljs.test :refer [async deftest is testing]]
            [electron.ipc :as ipc]
            [frontend.common.user :as common-user]
            [frontend.handler.user :as user-handler]
            [frontend.state :as state]
            [frontend.util :as util]
            [frontend.wallet :as wallet]
            [promesa.core :as p]))

(defn- with-mocked-local-storage
  "Runs `(f store)` with an in-memory localStorage seeded from `items`."
  ([f]
   (with-mocked-local-storage {} f))
  ([items f]
   (let [old-storage (.-localStorage js/globalThis)
         had-local-storage?
         (.call (.-hasOwnProperty (.-prototype js/Object))
                js/globalThis
                "localStorage")
         store (atom items)
         mocked-storage #js {:clear (fn [] (reset! store {}))
                             :setItem (fn [k v] (swap! store assoc k (str v)))
                             :getItem (fn [k] (get @store k))
                             :removeItem (fn [k] (swap! store dissoc k))}]
     (js/Object.defineProperty js/globalThis
                               "localStorage"
                               #js {:value mocked-storage
                                    :configurable true
                                    :writable true})
     (try
       (f store)
       (finally
         (if had-local-storage?
           (js/Object.defineProperty js/globalThis
                                     "localStorage"
                                     #js {:value old-storage
                                          :configurable true
                                          :writable true})
           (js/Reflect.deleteProperty js/globalThis "localStorage")))))))

(defn- jwt
  [payload]
  (str "header."
       (js/btoa (js/JSON.stringify (clj->js payload)))
       ".sig"))

(def ^:private address "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")

(def ^:private valid-claims {:sub address :username "Ada" :exp 4102444800})

(deftest login-with-token-installs-the-session-and-keeps-the-desktop-auth-file-test
  (let [writes* (atom [])
        events* (atom [])
        old-state (state/get-state)
        old-pub-event! state/pub-event!]
    (set! state/pub-event! (fn [event] (swap! events* conj event)))
    (try
      (with-mocked-local-storage
        (fn [store]
          (with-redefs [util/electron? (constantly true)
                        ipc/ipc (fn [op & args]
                                  (swap! writes* conj (into [op] args))
                                  (p/resolved nil))]
            (let [token (jwt valid-claims)]
              (user-handler/login-with-token! token)
              (is (= [[:session/write-token token]] @writes*))
              (is (= token (get @store "access-token")))
              (is (user-handler/logged-in?))
              (is (= address (user-handler/address)))
              (is (= "Ada" (user-handler/username)))
              (is (= "0xf39F…2266" (user-handler/short-address "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")))
              (is (= [[:user/signed-in]] @events*))
              (testing "tokens without the expected claims or already expired are refused"
                (is (thrown? js/Error (user-handler/login-with-token! (jwt {:sub address :exp 4102444800}))))
                (is (thrown? js/Error (user-handler/login-with-token! (jwt (assoc valid-claims :exp 1)))))
                (is (= token (user-handler/access-token))))
              (user-handler/logout)
              (is (not (user-handler/logged-in?)))
              (is (nil? (get @store "access-token")))
              (is (= [:session/remove-token] (last @writes*)))
              (is (= [:user/logout] (last @events*)))))))
      (finally
        (set! state/pub-event! old-pub-event!)
        (state/replace-state! old-state)))))

(deftest address-derives-a-stable-version-5-uuid-test
  (let [derived (common-user/address->uuid address)]
    (is (re-matches #"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}" derived))
    (is (util/uuid-string? derived))
    (is (= derived (common-user/address->uuid (.toUpperCase address))))
    (is (not= derived (common-user/address->uuid "0x0000000000000000000000000000000000000001")))))

(deftest restore-session-renews-an-expired-token-with-the-device-identity-test
  (async done
         (let [old-state (state/get-state)
               old-pub-event! state/pub-event!
               events* (atom [])
               fresh (jwt valid-claims)
               renewals* (atom 0)
               restore! (fn []
                          (set! state/pub-event! old-pub-event!)
                          (state/replace-state! old-state))]
           (set! state/pub-event! (fn [event] (swap! events* conj event)))
           (with-mocked-local-storage
             {"access-token" (jwt (assoc valid-claims :exp 1))}
             (fn [store]
               (-> (p/with-redefs [util/electron? (constantly false)
                                   wallet/<has-identity? (fn [] (p/resolved true))
                                   wallet/<renew-session! (fn [_]
                                                            (swap! renewals* inc)
                                                            (p/resolved {:access-token fresh
                                                                         :expires-in 60
                                                                         :address address}))]
                     (user-handler/restore-session!)
                     (p/delay 20))
                   (p/then (fn []
                             (is (= 1 @renewals*))
                             (is (= fresh (get @store "access-token")))
                             (is (user-handler/logged-in?))
                             (is (= [[:user/signed-in]] @events*))))
                   (p/catch (fn [error]
                              (is false (str error))))
                   (p/finally (fn []
                                (restore!)
                                (done)))))))))

(deftest restore-session-asks-to-sign-in-again-without-an-identity-test
  (async done
         (let [old-state (state/get-state)
               old-pub-event! state/pub-event!
               events* (atom [])
               restore! (fn []
                          (set! state/pub-event! old-pub-event!)
                          (state/replace-state! old-state))]
           (set! state/pub-event! (fn [event] (swap! events* conj event)))
           (with-mocked-local-storage
             {"access-token" (jwt (assoc valid-claims :exp 1))}
             (fn [store]
               (-> (p/with-redefs [util/electron? (constantly false)
                                   wallet/<has-identity? (fn [] (p/resolved false))]
                     (user-handler/restore-session!)
                     (p/delay 20))
                   (p/then (fn []
                             (is (nil? (get @store "access-token")))
                             (is (not (user-handler/logged-in?)))
                             (is (= [[:user/session-expired]] @events*))))
                   (p/catch (fn [error]
                              (is false (str error))))
                   (p/finally (fn []
                                (restore!)
                                (done)))))))))
