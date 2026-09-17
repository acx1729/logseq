(ns frontend.config-test
  (:require [cljs.test :refer [deftest is testing]]
            [frontend.config :as config]
            [frontend.state :as state]
            [logseq.common.config :as common-config]))

(deftest get-local-dir-uses-encoded-directory-name
  (with-redefs [state/get-state (fn [] {:system/info {:home-dir "/tmp/home"}})]
    (is (= "/tmp/home/logseq/graphs/foo~2Fbar"
           (config/get-local-dir (str common-config/db-version-prefix "foo/bar"))))))

(deftest get-electron-backup-dir-uses-unified-backup-directory
  (with-redefs [state/get-state (fn [] {:system/info {:home-dir "/tmp/home"}})]
    (is (= "/tmp/home/logseq/graphs/foo~2Fbar/backup"
           (config/get-electron-backup-dir (str common-config/db-version-prefix "foo/bar"))))))

(deftest sync-server-url->ws-url-test
  (testing "https URL becomes wss"
    (is (= "wss://my-server.example.com/sync/%s"
           (config/sync-server-url->ws-url "https://my-server.example.com"))))

  (testing "http URL becomes ws"
    (is (= "ws://localhost:8787/sync/%s"
           (config/sync-server-url->ws-url "http://localhost:8787"))))

  (testing "trailing slashes are stripped"
    (is (= "wss://my-server.example.com/sync/%s"
           (config/sync-server-url->ws-url "https://my-server.example.com/")))
    (is (= "wss://my-server.example.com/sync/%s"
           (config/sync-server-url->ws-url "https://my-server.example.com///"))))

  (testing "preserves port in URL"
    (is (= "wss://example.com:3000/sync/%s"
           (config/sync-server-url->ws-url "https://example.com:3000"))))

  (testing "preserves subpath in host"
    ;; Users should only provide a base URL, but verify trailing path doesn't break things
    (is (= "wss://example.com/api/sync/%s"
           (config/sync-server-url->ws-url "https://example.com/api")))))

(deftest sync-server-url->http-base-test
  (testing "returns URL as-is when no trailing slash"
    (is (= "https://my-server.example.com"
           (config/sync-server-url->http-base "https://my-server.example.com"))))

  (testing "strips trailing slashes"
    (is (= "https://my-server.example.com"
           (config/sync-server-url->http-base "https://my-server.example.com/")))
    (is (= "https://my-server.example.com"
           (config/sync-server-url->http-base "https://my-server.example.com///"))))

  (testing "preserves http scheme"
    (is (= "http://localhost:8787"
           (config/sync-server-url->http-base "http://localhost:8787"))))

  (testing "preserves port"
    (is (= "https://example.com:3000"
           (config/sync-server-url->http-base "https://example.com:3000/")))))

(deftest sync-urls-are-nil-without-a-sync-server
  (testing "no saved sync server means no sync URLs"
    ;; node-test? is true here, so no server can be saved
    (is (nil? (config/sync-server-url)))
    (is (nil? (config/db-sync-ws-url)))
    (is (nil? (config/db-sync-http-base)))))

(deftest valid-sync-server-url?-test
  (testing "accepts http and https URLs"
    (is (config/valid-sync-server-url? "https://my-server.example.com"))
    (is (config/valid-sync-server-url? "http://localhost:8787")))

  (testing "rejects non-URL strings"
    (is (not (config/valid-sync-server-url? "not a url")))
    (is (not (config/valid-sync-server-url? "")))
    (is (not (config/valid-sync-server-url? nil)))))
