(ns frontend.common.user
  "How a wallet address becomes the uuid graphs attribute a person by.
   Shared by the UI thread and the db worker so both derive the same page."
  (:require [clojure.string :as string]
            [goog.crypt :as crypt]
            [goog.crypt.Sha1]))

;; Graph content attributes people by a uuid (created-by, reactions,
;; comments, deletions). Wallet identities are addresses, so every client
;; derives the same version-5 uuid from the lowercase address.
(def ^:private uuid-namespace "b6a4e1e1-2f3c-4e5c-9c0b-7c1a5b2d9e10")

(defn address->uuid
  "The version-5 uuid string for `address`, the same on every device."
  [address]
  (let [hasher (doto (goog.crypt.Sha1.)
                 (.update (crypt/hexToByteArray (string/replace uuid-namespace "-" "")))
                 (.update (crypt/stringToUtf8ByteArray (string/lower-case address))))
        digest (vec (take 16 (.digest hasher)))
        bytes' (-> digest
                   (update 6 #(bit-or (bit-and % 0x0f) 0x50))
                   (update 8 #(bit-or (bit-and % 0x3f) 0x80)))
        hex (crypt/byteArrayToHex (clj->js bytes'))]
    (str (subs hex 0 8) "-" (subs hex 8 12) "-" (subs hex 12 16) "-"
         (subs hex 16 20) "-" (subs hex 20 32))))
