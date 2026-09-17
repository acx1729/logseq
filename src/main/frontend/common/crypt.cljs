(ns frontend.common.crypt
  "AES-GCM helpers over WebCrypto, shared by the worker and the app."
  (:require [lambdaisland.glogi :as log]
            [logseq.db :as ldb]
            [promesa.core :as p]))

(defonce subtle (.. js/crypto -subtle))

(defn <export-aes-key
  [aes-key]
  (assert (instance? js/CryptoKey aes-key))
  (p/let [exported (.exportKey subtle "raw" aes-key)]
    (js/Uint8Array. exported)))

(defn <import-aes-key
  [exported-aes-key]
  (assert (instance? js/Uint8Array exported-aes-key))
  (.importKey subtle
              "raw"
              exported-aes-key
              "AES-GCM"
              true
              #js ["encrypt" "decrypt"]))

(defn <generate-aes-key
  "Generates a new AES-GCM-256 key."
  []
  (.generateKey subtle
                #js {:name "AES-GCM"
                     :length 256}
                true
                #js ["encrypt" "decrypt"]))

(defn <encrypt-uint8array
  [aes-key arr]
  (assert (and (instance? js/CryptoKey aes-key) (instance? js/Uint8Array arr)))
  (p/let [iv (js/crypto.getRandomValues (js/Uint8Array. 12))
          encrypted-data (.encrypt subtle
                                   #js {:name "AES-GCM" :iv iv}
                                   aes-key
                                   arr)]
    [iv (js/Uint8Array. encrypted-data)]))

(defn <decrypt-uint8array
  [aes-key encrypted-data-vector]
  (->
   (p/let [[iv-data encrypted-data] encrypted-data-vector
           _ (assert (instance? js/Uint8Array encrypted-data))
           iv (js/Uint8Array. iv-data)
           decrypted-data (.decrypt subtle
                                    #js {:name "AES-GCM" :iv iv}
                                    aes-key
                                    encrypted-data)]
     (js/Uint8Array. decrypted-data))
   (p/catch
    (fn [e]
      (log/error "decrypt-uint8array" e)
      (ex-info "decrypt-uint8array" {} e)))))

(defn <encrypt-text
  "Encrypts text with an AES key."
  [aes-key text]
  (assert (and (string? text) (ldb/read-transit-str text)) "text must be transit-encoded")
  (assert (instance? js/CryptoKey aes-key))
  (p/let [iv (js/crypto.getRandomValues (js/Uint8Array. 12))
          encoded-text (.encode (js/TextEncoder.) text)
          encrypted-data (.encrypt subtle
                                   #js {:name "AES-GCM" :iv iv}
                                   aes-key
                                   encoded-text)]
    [iv (js/Uint8Array. encrypted-data)]))

(defn <decrypt-text
  "Decrypts text with an AES key."
  [aes-key encrypted-text-data-vector]
  (-> (p/let [[iv-data encrypted-data] encrypted-text-data-vector
              iv (js/Uint8Array. iv-data)
              encrypted-data (js/Uint8Array. encrypted-data)
              decrypted-data (.decrypt subtle
                                       #js {:name "AES-GCM" :iv iv}
                                       aes-key
                                       encrypted-data)
              decoded-text (.decode (js/TextDecoder.) decrypted-data)]
        decoded-text)
      (p/catch
       (fn [e]
         (log/error "decrypt-text" e)
         (ex-info "decrypt-text" {} e)))))

(defn <decrypt-text-if-encrypted
  "return nil if not a encrypted-package"
  [aes-key maybe-encrypted-package]
  (when (and (vector? maybe-encrypted-package)
             (<= 2 (count maybe-encrypted-package)))
    (<decrypt-text aes-key maybe-encrypted-package)))
