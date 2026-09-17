(ns frontend.common.crypt-test
  (:require [cljs.test :as t :refer [is testing]]
            [frontend.common.crypt :as crypt]
            [frontend.test.helper :as test-helper :include-macros true :refer [deftest-async]]
            [logseq.db :as ldb]
            [promesa.core :as p]))

(defn- uint8array=? [arr1 arr2]
  (assert (and (instance? js/Uint8Array arr1)
               (instance? js/Uint8Array arr2)))
  (= (vec arr1) (vec arr2)))

(deftest-async aes-key-export-import-and-roundtrips-test
  (p/let [aes-key (crypt/<generate-aes-key)
          exported (crypt/<export-aes-key aes-key)
          imported (crypt/<import-aes-key exported)
          exported-again (crypt/<export-aes-key imported)
          text (ldb/write-transit-str "hello")
          encrypted-text (crypt/<encrypt-text aes-key text)
          decrypted-text (crypt/<decrypt-text imported encrypted-text)
          bytes (js/Uint8Array. #js [1 2 3 4 5])
          encrypted-bytes (crypt/<encrypt-uint8array aes-key bytes)
          decrypted-bytes (crypt/<decrypt-uint8array imported encrypted-bytes)]
    (testing "a raw 32 byte export imports to the same key"
      (is (= 32 (.-length exported)))
      (is (uint8array=? exported exported-again)))
    (testing "text and bytes roundtrip through AES-GCM with a fresh iv each time"
      (is (vector? encrypted-text))
      (is (instance? js/Uint8Array (first encrypted-text)))
      (is (= text decrypted-text))
      (is (uint8array=? bytes decrypted-bytes)))
    (testing "another key cannot decrypt, and non-packages are not decrypted"
      (p/do!
       (p/let [other-key (crypt/<generate-aes-key)]
         (-> (crypt/<decrypt-text other-key encrypted-text)
             (p/then (fn [result] (is (= "decrypt-text" (ex-message result)))))))
       (is (nil? (crypt/<decrypt-text-if-encrypted aes-key "plain")))))))
