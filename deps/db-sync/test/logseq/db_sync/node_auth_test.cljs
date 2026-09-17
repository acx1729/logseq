(ns logseq.db-sync.node-auth-test
  "End-to-end wallet sign-in against a running Node adapter: tokens, display
  names, the client configuration, refusals, and membership removal cutting
  sockets."
  (:require ["viem/accounts" :as accounts]
            ["viem/siwe" :as viem-siwe]
            ["ws" :as ws]
            [cljs.test :refer [async deftest is]]
            [clojure.string :as string]
            [logseq.db-sync.test-server :as test-server]
            [promesa.core :as p]))

(def ^:private issuer "http://127.0.0.1")

(defn- new-account []
  (accounts/privateKeyToAccount (accounts/generatePrivateKey)))

(defn- <json [^js response]
  (p/let [body (.json response)]
    {:status (.-status response)
     :body body}))

(defn- <signed-message
  "A fresh nonce signed by `account`; `opts` override the message's chain id,
  domain and uri, which default to what a desktop or CLI client sends."
  ([base-url account] (<signed-message base-url account {}))
  ([base-url ^js account {:keys [chain-id domain uri]
                          :or {chain-id 1 domain "127.0.0.1" uri issuer}}]
   (p/let [nonce-response (js/fetch (str base-url "/auth/nonce"))
           {:keys [body]} (<json nonce-response)
           message (viem-siwe/createSiweMessage
                    #js {:address (.-address account)
                         :chainId chain-id
                         :domain domain
                         :nonce (aget body "nonce")
                         :uri uri
                         :version "1"
                         :statement "Sign in to Logseq"
                         :issuedAt (js/Date.)})
           signature (.signMessage account #js {:message message})]
     {:message message :signature signature})))

(defn- <post-siwe [base-url payload]
  (p/let [response (js/fetch (str base-url "/auth/siwe")
                             #js {:method "POST"
                                  :headers #js {"content-type" "application/json"}
                                  :body (js/JSON.stringify (clj->js payload))})]
    (<json response)))

(defn- <sign-in
  "Signs `account` in and resolves to its token; `username` is sent when given."
  ([base-url account] (<sign-in base-url account nil))
  ([base-url account username]
   (p/let [signed (<signed-message base-url account)
           {:keys [status body]} (<post-siwe base-url (cond-> signed
                                                       username (assoc :username username)))]
     (when-not (= 200 status)
       (throw (ex-info "sign-in failed" {:status status :body (js/JSON.stringify body)})))
     (aget body "access_token"))))

(defn- token-claims [token]
  (-> (second (string/split token #"\."))
      (js/Buffer.from "base64url")
      (.toString "utf8")
      js/JSON.parse))

(defn- <fetch-json [base-url path token & [init]]
  (p/let [response (js/fetch (str base-url path)
                             (clj->js (merge {:headers (cond-> {"content-type" "application/json"}
                                                         token (assoc "authorization" (str "Bearer " token)))}
                                             init)))]
    (<json response)))

(defn- with-server
  "Starts an adapter with `overrides`, runs `(f base-url port)` and stops it
  whatever happens."
  ([prefix f done] (with-server prefix {} f done))
  ([prefix overrides f done]
   (-> (p/let [{:keys [base-url port stop!]} (test-server/start! prefix overrides)]
         (-> (p/do (f base-url port))
             (p/catch (fn [error]
                        (is false (str error))))
             (p/then (fn [] (stop!)))))
       (p/catch (fn [error]
                  (is false (str error))))
       (p/then (fn [] (done))))))

(deftest siwe-sign-in-issues-token-that-authorizes-graph-requests-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/direct/"
           (fn [base-url _port]
             (p/let [account (new-account)
                     signed (<signed-message base-url account)
                     {:keys [status body]} (<post-siwe base-url signed)
                     token (aget body "access_token")
                     graphs (<fetch-json base-url "/graphs" token)
                     anonymous (<fetch-json base-url "/graphs" nil)
                     jwks (<fetch-json base-url "/auth/jwks.json" nil)
                     replay (<post-siwe base-url signed)]
               (is (= 200 status))
               (is (string? token))
               (is (= ["access_token" "expires_in" "scope" "token_type"]
                      (sort (js/Object.keys body))))
               (is (= "Bearer" (aget body "token_type")))
               (is (= (* 30 24 60 60) (aget body "expires_in")))
               (is (= (.toLowerCase (.-address account)) (aget (token-claims token) "sub")))
               (is (= 11 (count (aget (token-claims token) "username"))))
               (is (= 200 (:status graphs)))
               (is (= 0 (count (aget (:body graphs) "graphs"))))
               (is (= 401 (:status anonymous)))
               (is (= 200 (:status jwks)))
               (is (= 1 (count (aget (:body jwks) "keys"))))
               (is (= "RS256" (aget (first (aget (:body jwks) "keys")) "alg")))
               (is (= 400 (:status replay)))
               (is (= "invalid_nonce" (aget (:body replay) "error")))))
           done)))

(deftest siwe-sign-in-refuses-foreign-domains-chains-and-forged-tokens-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/refuse/"
           (fn [base-url _port]
             (p/let [account (new-account)
                     foreign (<signed-message base-url account {:domain "evil.example.test"
                                                                :uri "https://evil.example.test/"})
                     refused (<post-siwe base-url foreign)
                     other-chain (<signed-message base-url account {:chain-id 10})
                     wrong-chain (<post-siwe base-url other-chain)
                     form (js/fetch (str base-url "/auth/siwe")
                                    #js {:method "POST"
                                         :headers #js {"content-type" "application/x-www-form-urlencoded"}
                                         :body "message=x&signature=0x00"})
                     forged (<fetch-json base-url "/graphs" "forged.token.value")]
               (is (= 400 (:status refused)))
               (is (= "siwe_domain_not_allowed" (aget (:body refused) "error")))
               (is (= 400 (:status wrong-chain)))
               (is (= "siwe_chain_not_allowed" (aget (:body wrong-chain) "error")))
               (is (= 415 (.-status form)))
               (is (= 401 (:status forged)))))
           done)))

(deftest sign-in-stores-and-keeps-display-names-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/names/"
           (fn [base-url _port]
             (p/let [account (new-account)
                     named (<sign-in base-url account "Ada Lovelace")
                     unnamed (<sign-in base-url account)
                     renamed (<sign-in base-url account "Ada")
                     signed (<signed-message base-url account)
                     blank (<post-siwe base-url (assoc signed :username "  "))
                     created (<fetch-json base-url "/graphs" renamed
                                          {:method "POST"
                                           :body (js/JSON.stringify #js {"graph-name" "notes"
                                                                         "schema-version" "65"})})
                     graph-id (aget (:body created) "graph-id")
                     members (<fetch-json base-url (str "/graphs/" graph-id "/members") renamed)]
               (is (= "Ada Lovelace" (aget (token-claims named) "username")))
               (is (= "Ada Lovelace" (aget (token-claims unnamed) "username")))
               (is (= "Ada" (aget (token-claims renamed) "username")))
               (is (= 400 (:status blank)))
               (is (= "invalid_username" (aget (:body blank) "error")))
               (is (= 200 (:status members)))
               (is (= ["Ada"] (mapv #(aget % "username") (aget (:body members) "members"))))))
           done)))

(deftest auth-config-publishes-client-settings-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/config/"
           {:siwe-chain-ids [1 10]
            :rpc-urls {1 "https://rpc.example.test"}
            :walletconnect-project-id "wc-project"
            :app-name "Hobby Notes"}
           (fn [base-url _port]
             (p/let [config (<fetch-json base-url "/auth/config" nil)
                     account (new-account)
                     on-optimism (<signed-message base-url account {:chain-id 10})
                     signed-in (<post-siwe base-url on-optimism)]
               (is (= 200 (:status config)))
               (is (= {"issuer" issuer
                       "app_name" "Hobby Notes"
                       "statement" "Sign in to Logseq"
                       "chain_ids" [1 10]
                       "rpc_urls" {"1" "https://rpc.example.test"}
                       "walletconnect_project_id" "wc-project"}
                      (js->clj (:body config))))
               (is (= 200 (:status signed-in)))))
           done)))

(defn- <open-socket [url]
  (p/create
   (fn [resolve reject]
     (let [WS (or (.-WebSocket ws) ws)
           socket (new WS url)
           timer (js/setTimeout (fn [] (reject (ex-info "socket did not open" {}))) 5000)]
       (.on socket "open" (fn []
                            (js/clearTimeout timer)
                            (resolve socket)))
       (.on socket "error" (fn [error]
                             (js/clearTimeout timer)
                             (reject error)))))))

(defn- <close-code [^js socket]
  (p/create
   (fn [resolve reject]
     (let [timer (js/setTimeout (fn [] (reject (ex-info "socket was not closed" {}))) 5000)]
       (.on socket "close" (fn [code]
                             (js/clearTimeout timer)
                             (resolve code)))))))

(deftest removing-a-member-closes-their-socket-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/members/"
           (fn [base-url port]
             (p/let [manager (new-account)
                     member (new-account)
                     manager-token (<sign-in base-url manager)
                     member-token (<sign-in base-url member)
                     member-id (.toLowerCase (.-address member))
                     created (<fetch-json base-url "/graphs" manager-token
                                          {:method "POST"
                                           :body (js/JSON.stringify #js {"graph-name" "shared"
                                                                         "schema-version" "65"})})
                     graph-id (aget (:body created) "graph-id")
                     added (<fetch-json base-url (str "/graphs/" graph-id "/members") manager-token
                                        {:method "POST"
                                         :body (js/JSON.stringify #js {"user-id" member-id
                                                                       "role" "member"})})
                     member-access (<fetch-json base-url (str "/graphs/" graph-id "/access") member-token)
                     member-key (<fetch-json base-url (str "/graphs/" graph-id "/key") member-token)
                     manager-key (<fetch-json base-url (str "/graphs/" graph-id "/key") manager-token)
                     socket (<open-socket (str "ws://127.0.0.1:" port "/sync/" graph-id "?token=" member-token))
                     close-code (<close-code socket)
                     removed (<fetch-json base-url (str "/graphs/" graph-id "/members/" member-id) manager-token
                                          {:method "DELETE"})
                     code close-code
                     member-access-after (<fetch-json base-url (str "/graphs/" graph-id "/access") member-token)
                     member-key-after (<fetch-json base-url (str "/graphs/" graph-id "/key") member-token)]
               (is (= 200 (:status created)))
               (is (true? (aget (:body created) "graph-e2ee?")))
               (is (= 200 (:status member-key)))
               (is (= 32 (.-length (js/Buffer.from (aget (:body member-key) "key") "base64"))))
               (is (= (aget (:body manager-key) "key") (aget (:body member-key) "key")))
               (is (= 200 (:status added)))
               (is (= 200 (:status member-access)))
               (is (= 200 (:status removed)))
               (is (= 4003 code))
               (is (= 403 (:status member-access-after)))
               (is (= 403 (:status member-key-after)))))
           done)))
