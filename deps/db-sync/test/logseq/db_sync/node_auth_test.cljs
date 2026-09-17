(ns logseq.db-sync.node-auth-test
  "End-to-end wallet sign-in against a running Node adapter: the direct flow,
  the PKCE code flow used by the CLI, and membership removal cutting sockets."
  (:require ["node:crypto" :as crypto]
            ["viem/accounts" :as accounts]
            ["viem/siwe" :as viem-siwe]
            ["ws" :as ws]
            [cljs.test :refer [async deftest is]]
            [logseq.db-sync.test-server :as test-server]
            [promesa.core :as p]))

(def ^:private redirect-uri "http://localhost:8765/auth/callback")

(defn- new-account []
  (accounts/privateKeyToAccount (accounts/generatePrivateKey)))

(defn- <json [^js response]
  (p/let [body (.json response)]
    {:status (.-status response)
     :body body}))

(defn- <signed-message [base-url ^js account]
  (p/let [nonce-response (js/fetch (str base-url "/auth/nonce"))
          {:keys [body]} (<json nonce-response)
          message (viem-siwe/createSiweMessage
                   #js {:address (.-address account)
                        :chainId 1
                        :domain "localhost"
                        :nonce (aget body "nonce")
                        :uri "http://localhost/auth/siwe/start"
                        :version "1"
                        :statement "Sign in to Logseq"
                        :issuedAt (js/Date.)})
          signature (.signMessage account #js {:message message})]
    {:message message :signature signature}))

(defn- <post-siwe [base-url payload]
  (p/let [response (js/fetch (str base-url "/auth/siwe")
                             #js {:method "POST"
                                  :headers #js {"content-type" "application/json"}
                                  :body (js/JSON.stringify (clj->js payload))})]
    (<json response)))

(defn- <sign-in [base-url account]
  (p/let [signed (<signed-message base-url account)
          {:keys [status body]} (<post-siwe base-url signed)]
    (when-not (= 200 status)
      (throw (ex-info "sign-in failed" {:status status :body (js/JSON.stringify body)})))
    (aget body "access_token")))

(defn- <fetch-json [base-url path token & [init]]
  (p/let [response (js/fetch (str base-url path)
                             (clj->js (merge {:headers (cond-> {"content-type" "application/json"}
                                                         token (assoc "authorization" (str "Bearer " token)))}
                                             init)))]
    (<json response)))

(defn- pkce-challenge [verifier]
  (-> (.createHash crypto "sha256")
      (.update verifier "utf8")
      (.digest "base64url")))

(defn- with-server
  "Starts an adapter, runs `(f base-url port)` and stops it whatever happens."
  [prefix f done]
  (-> (p/let [{:keys [base-url port stop!]} (test-server/start! prefix)]
        (-> (p/do (f base-url port))
            (p/catch (fn [error]
                       (is false (str error))))
            (p/then (fn [] (stop!)))))
      (p/catch (fn [error]
                 (is false (str error))))
      (p/then (fn [] (done)))))

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
               (is (= "Bearer" (aget body "token_type")))
               (is (= (* 30 24 60 60) (aget body "expires_in")))
               (is (= 200 (:status graphs)))
               (is (= 0 (count (aget (:body graphs) "graphs"))))
               (is (= 401 (:status anonymous)))
               (is (= 200 (:status jwks)))
               (is (= 1 (count (aget (:body jwks) "keys"))))
               (is (= "RS256" (aget (first (aget (:body jwks) "keys")) "alg")))
               (is (= 400 (:status replay)))
               (is (= "invalid_nonce" (aget (:body replay) "error")))))
           done)))

(deftest siwe-sign-in-refuses-foreign-domains-and-forged-tokens-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/refuse/"
           (fn [base-url _port]
             (p/let [account (new-account)
                     nonce-response (js/fetch (str base-url "/auth/nonce"))
                     {:keys [body]} (<json nonce-response)
                     message (viem-siwe/createSiweMessage
                              #js {:address (.-address account)
                                   :chainId 1
                                   :domain "evil.example.test"
                                   :nonce (aget body "nonce")
                                   :uri "https://evil.example.test/"
                                   :version "1"
                                   :issuedAt (js/Date.)})
                     signature (.signMessage account #js {:message message})
                     refused (<post-siwe base-url {:message message :signature signature})
                     forged (<fetch-json base-url "/graphs" "forged.token.value")]
               (is (= 400 (:status refused)))
               (is (= "siwe_domain_not_allowed" (aget (:body refused) "error")))
               (is (= 401 (:status forged)))))
           done)))

(deftest code-flow-exchanges-pkce-code-for-token-test
  (async done
         (with-server
           "tmp/db-sync-node-auth-test/code/"
           (fn [base-url _port]
             (let [verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                   challenge (pkce-challenge verifier)]
               (p/let [account (new-account)
                       page (js/fetch (str base-url "/auth/siwe/start?response_type=code&client_id=logseq-sync&state=abc"
                                           "&redirect_uri=" (js/encodeURIComponent redirect-uri)
                                           "&code_challenge=" challenge "&code_challenge_method=S256"))
                       page-html (.text page)
                       bad-page (js/fetch (str base-url "/auth/siwe/start?state=abc&redirect_uri="
                                               (js/encodeURIComponent "https://evil.example.test/cb")
                                               "&code_challenge=" challenge "&code_challenge_method=S256"))
                       signed (<signed-message base-url account)
                       {:keys [status body]} (<post-siwe base-url (assoc signed
                                                                        :code_challenge challenge
                                                                        :code_challenge_method "S256"
                                                                        :redirect_uri redirect-uri))
                       code (aget body "code")
                       form (str "grant_type=authorization_code&code=" (js/encodeURIComponent code)
                                 "&redirect_uri=" (js/encodeURIComponent redirect-uri)
                                 "&code_verifier=" verifier "&client_id=logseq-sync")
                       token-response (js/fetch (str base-url "/auth/token")
                                                #js {:method "POST"
                                                     :headers #js {"content-type" "application/x-www-form-urlencoded"}
                                                     :body form})
                       token-body (<json token-response)
                       graphs (<fetch-json base-url "/graphs" (aget (:body token-body) "access_token"))
                       reuse (js/fetch (str base-url "/auth/token")
                                       #js {:method "POST"
                                            :headers #js {"content-type" "application/x-www-form-urlencoded"}
                                            :body form})]
                 (is (= 200 (.-status page)))
                 (is (re-find #"script-src 'sha256-" (.get (.-headers page) "content-security-policy")))
                 (is (re-find #"siwe-params" page-html))
                 (is (= 400 (.-status bad-page)))
                 (is (= 200 status))
                 (is (string? code))
                 (is (= 200 (:status token-body)))
                 (is (string? (aget (:body token-body) "id_token")))
                 (is (= 200 (:status graphs)))
                 (is (= 400 (.-status reuse))))))
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
                                                                         "schema-version" "65"
                                                                         "graph-e2ee?" false})})
                     graph-id (aget (:body created) "graph-id")
                     added (<fetch-json base-url (str "/graphs/" graph-id "/members") manager-token
                                        {:method "POST"
                                         :body (js/JSON.stringify #js {"user-id" member-id
                                                                       "role" "member"})})
                     member-access (<fetch-json base-url (str "/graphs/" graph-id "/access") member-token)
                     socket (<open-socket (str "ws://127.0.0.1:" port "/sync/" graph-id "?token=" member-token))
                     close-code (<close-code socket)
                     removed (<fetch-json base-url (str "/graphs/" graph-id "/members/" member-id) manager-token
                                          {:method "DELETE"})
                     code close-code
                     member-access-after (<fetch-json base-url (str "/graphs/" graph-id "/access") member-token)]
               (is (= 200 (:status created)))
               (is (= 200 (:status added)))
               (is (= 200 (:status member-access)))
               (is (= 200 (:status removed)))
               (is (= 4003 code))
               (is (= 403 (:status member-access-after)))))
           done)))
