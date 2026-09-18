(ns frontend.config
  "App config and fns built on top of configuration"
  (:require [clojure.set :as set]
            [clojure.string :as string]
            [frontend.state :as state]
            [frontend.util :as util]
            [goog.crypt.Md5]
            [logseq.common.config :as common-config]
            [logseq.common.graph-dir :as common-graph-dir]
            [logseq.common.path :as path]
            [logseq.db.sqlite.util :as sqlite-util]
            [shadow.resource :as rc]))

(goog-define DEV-RELEASE false)
(defonce dev-release? DEV-RELEASE)
(defonce dev? ^boolean (or dev-release? goog.DEBUG))

(defonce publishing? common-config/PUBLISHING)

(def default-publish-api-base "https://logseq.io")

;; Enable for local development
;; (def default-publish-api-base "http://localhost:8787")

(defn sync-server-url
  "The self-hosted sync server this app talks to, kept in this browser
   profile. nil until the person sets one."
  []
  (when-not util/node-test?
    (let [v (.getItem js/localStorage "sync-server-url")]
      (when (and (string? v) (not (string/blank? v)))
        v))))

(defn set-sync-server-url!
  "Saves the sync server address; nil or blank clears it."
  [url]
  (when-not util/node-test?
    (if (or (nil? url) (string/blank? url))
      (.removeItem js/localStorage "sync-server-url")
      (.setItem js/localStorage "sync-server-url" (string/trim url)))))

(defn sync-server-prompt-dismissed?
  "True once the person closed the startup prompt without setting a server."
  []
  (when-not util/node-test?
    (= "true" (.getItem js/localStorage "sync-server-prompt-dismissed"))))

(defn dismiss-sync-server-prompt!
  []
  (when-not util/node-test?
    (.setItem js/localStorage "sync-server-prompt-dismissed" "true")))

(defn valid-sync-server-url?
  "Return true when `url` looks like a valid HTTP(S) base URL."
  [url]
  (and (string? url)
       (re-find #"^https?://" url)))

(defn sync-server-url->ws-url
  "Derive a WebSocket sync URL from the server's HTTP base URL. Pure function."
  [server-url]
  (let [scheme (if (string/starts-with? server-url "https") "wss" "ws")
        base (-> server-url
                 (string/replace #"^https?://" "")
                 (string/replace #"/+$" ""))]
    (str scheme "://" base "/sync/%s")))

(defn sync-server-url->http-base
  "Normalize the server's HTTP base URL by stripping trailing slashes. Pure function."
  [server-url]
  (string/replace server-url #"/+$" ""))

(defn db-sync-ws-url
  "The WebSocket sync URL, or nil while no sync server is set."
  []
  (some-> (sync-server-url) sync-server-url->ws-url))

(defn db-sync-http-base
  "The HTTP base URL of the sync server, or nil while none is set."
  []
  (some-> (sync-server-url) sync-server-url->http-base))

(defn get-custom-publish-server-url
  "Read the user-configured custom publish server URL from localStorage.
   Returns nil when not set or empty."
  []
  (when-not util/node-test?
    (let [v (.getItem js/localStorage "publish-server-url")]
      (when (and (string? v) (not (string/blank? v)))
        v))))

(defn set-custom-publish-server-url!
  "Persist the custom publish server URL to localStorage. Pass nil or empty string to clear."
  [url]
  (when-not util/node-test?
    (if (or (nil? url) (string/blank? url))
      (.removeItem js/localStorage "publish-server-url")
      (.setItem js/localStorage "publish-server-url" (string/trim url)))))

(defn valid-publish-server-url?
  "Return true when `url` looks like a valid HTTP(S) base URL."
  [url]
  (and (string? url)
       (re-find #"^https?://" url)))

(defn custom-url->publish-api-base
  "Normalize a custom publish base URL by stripping trailing slashes. Pure function."
  [custom-url]
  (string/replace custom-url #"/+$" ""))

(defn publish-api-base
  "Return the base URL for the single-page publish service. Uses the user-configured
   URL from localStorage when set, otherwise the default url above. Read on each call so URL changes take effect without a restart."
  []
  (if-let [custom (get-custom-publish-server-url)]
    (custom-url->publish-api-base custom)
    default-publish-api-base))

;; Feature flags
;; =============

(goog-define ENABLE-PLUGINS true)
(defonce feature-plugin-system-on? ENABLE-PLUGINS)

;; Desktop only as other platforms requires better understanding of their
;; multi-graph workflows and optimal place for a "global" dir
(def global-config-enabled? util/electron?)

;; User level configuration for whether plugins are enabled
(defonce lsp-enabled?
  (and util/plugin-platform?
       (not (false? feature-plugin-system-on?))
       (state/lsp-enabled?-or-theme)))

(defn plugin-config-enabled?
  []
  (and lsp-enabled? (global-config-enabled?)))

;; :TODO: How to do this?
;; (defonce desktop? ^boolean goog.DESKTOP)

;; ============

(def app-name common-config/app-name)

;; FIXME:
(def app-website
  (if dev?
    "http://localhost:3001"
    (util/format "https://%s.com" app-name)))

(def markup-formats
  #{:org :md :markdown :asciidoc :adoc :rst})

(def doc-formats
  #{:doc :docx :xls :xlsx :ppt :pptx :one :pdf :epub})

(def image-formats
  #{:png :jpg :jpeg :bmp :gif :webp :svg :heic :avif :cr2})

(def audio-formats
  #{:mp3 :ogg :mpeg :wav :m4a :flac :wma :aac})

(def video-formats
  #{:mp4 :webm :mov :flv :avi :mkv})

(def media-formats (set/union (common-config/img-formats) audio-formats video-formats))

(def mobile?
  "Triggering condition: Mobile phones
   *** Warning!!! ***
   For UX logic only! Don't use for FS logic
   iPad / Android Pad doesn't trigger!

   Same as config/mobile?"
  (when-not util/node-test?
    (util/safe-re-find #"Mobi" js/navigator.userAgent)))

(defn get-hr
  [format]
  (let [format (or format (keyword (state/get-preferred-format)))]
    (case format
      :markdown
      "---"
      "")))

(defn get-bold
  [format]
  (let [format (or format (keyword (state/get-preferred-format)))]
    (case format
      :markdown
      "**"
      "")))

(defn get-italic
  [format]
  (let [format (or format (keyword (state/get-preferred-format)))]
    (case format
      :markdown
      "*"
      "")))
(defn get-underline
  [format]
  (let [format (or format (keyword (state/get-preferred-format)))]
    (case format
      :markdown ;; no underline for markdown
      ""
      "")))
(defn get-strike-through
  [format]
  (let [format (or format (keyword (state/get-preferred-format)))]
    (case format
      :markdown
      "~~"
      "")))

(defn get-highlight
  [format]
  (case format
    :markdown
    "=="
    ""))

(defn get-code
  [format]
  (let [format (or format (keyword (state/get-preferred-format)))]
    (case format
      :markdown
      "`"
      "")))

(defn get-empty-link-and-forward-pos
  [format]
  (case format
    :markdown
    ["[]()" 1]
    ["" 0]))

(defn link-format
  [label link]
  (if (not-empty label)
    (util/format "[%s](%s)" label link)
    link))

(defn with-default-link
  [format link]
  (case format
    :markdown
    [(util/format "[](%s)" link)
     1]
    ["" 0]))

(defn with-label-link
  [format label link]
  (case format
    :markdown
    [(util/format "[%s](%s)" label link)
     (+ 4 (count link) (count label))]
    ["" 0]))

(defn with-default-label
  [format label]
  (case format
    :markdown
    [(util/format "[%s]()" label)
     (+ 3 (count label))]
    ["" 0]))

(defonce demo-repo "Demo")

(defn demo-graph?
  "Demo graph or nil graph?"
  ([]
   (demo-graph? (state/get-current-repo)))
  ([repo-url]
   (or (nil? repo-url) (= repo-url demo-repo)
       (string/ends-with? repo-url demo-repo))))

(def config-file "config.edn")
(def custom-css-file "custom.css")
(def export-css-file "export.css")
(def custom-js-file "custom.js")
(def config-default-content (rc/inline "templates/config.edn"))

;; NOTE: repo-url is the unique identifier of a repo.
;; - `logseq_db_GraphName` => db based graph, sqlite as backend
;; - Use `""` while writing global files

(defonce db-version-prefix common-config/db-version-prefix)

(defn db-graph-name
  [repo-with-prefix]
  (common-config/strip-leading-db-version-prefix repo-with-prefix))

(defn db-based-graph?
  ([]
   (db-based-graph? (state/get-current-repo)))
  ([s]
   (boolean
    (and (string? s)
         (sqlite-util/db-based-graph? s)))))

(defn get-local-asset-absolute-path
  [s]
  (str "/" (string/replace s #"^[./]*" "")))

(defn get-local-dir
  [repo]
  (path/path-join (get-in (state/get-state) [:system/info :home-dir])
                  "logseq"
                  "graphs"
                  (common-graph-dir/repo->encoded-graph-dir-name repo)))

(defn get-electron-backup-dir
  [repo]
  (path/path-join (get-local-dir repo) "backup"))

(defn get-repo-dir
  [repo-url]
  (when repo-url
    (if (util/electron?)
      (get-local-dir repo-url)
      (str "memory:///"
           (db-graph-name repo-url)))))

(defn get-repo-config-path
  []
  (path/path-join app-name config-file))

(defn get-custom-css-path
  ([]
   (get-custom-css-path (state/get-current-repo)))
  ([repo]
   (if (db-based-graph? repo)
     (path/path-join app-name custom-css-file)
     (when-let [repo-dir (get-repo-dir repo)]
       (path/path-join repo-dir app-name custom-css-file)))))

(defn get-export-css-path
  ([]
   (get-export-css-path (state/get-current-repo)))
  ([repo]
   (when-let [repo-dir (get-repo-dir repo)]
     (path/path-join repo-dir app-name  export-css-file))))

(defn get-repo-assets-root
  [repo]
  (when-let [repo-dir (get-repo-dir repo)]
    (path/path-join repo-dir "assets")))

(defn get-current-repo-assets-root
  []
  (get-repo-assets-root (state/get-current-repo)))

(defn get-custom-js-path
  ([]
   (get-custom-js-path (state/get-current-repo)))
  ([repo]
   (if (db-based-graph? repo)
     (path/path-join app-name custom-js-file)
     (when-let [repo-dir (get-repo-dir repo)]
       (path/path-join repo-dir app-name custom-js-file)))))
