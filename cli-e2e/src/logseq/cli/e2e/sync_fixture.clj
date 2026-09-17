(ns logseq.cli.e2e.sync-fixture
  (:require [babashka.fs :as fs]
            [clojure.string :as string]
            [logseq.cli.e2e.paths :as paths]
            [logseq.cli.e2e.runner :as runner]
            [logseq.cli.e2e.shell :as shell]))

(def default-sync-port "18080")

(def ^:private heavy-setup-patterns
  [#"^mkdir -p '\{\{tmp-dir\}\}/home/logseq'$"
   #"^cp .*auth\.json"
   #"prepare_sync_config\.py"
   #"db_sync_server\.py'? start"])

(def ^:private heavy-cleanup-patterns
  [#"db_sync_server\.py'? stop"])

(defn- shell-quote
  [value]
  (runner/shell-escape value))

(defn- heavy-command?
  [command patterns]
  (boolean (some #(re-find % command) patterns)))

(defn- case-local-setup-prefix
  []
  ["mkdir -p '{{tmp-dir}}/home/logseq'"
   "cp '{{suite-auth-path}}' '{{tmp-dir}}/home/logseq/auth.json'"
   "python3 '{{repo-root}}/cli-e2e/scripts/prepare_sync_config.py' --output '{{config-path}}' --auth-path '{{tmp-dir}}/home/logseq/auth.json' --http-base '{{sync-http-base}}' --ws-url '{{sync-ws-url}}'"
   "python3 '{{repo-root}}/cli-e2e/scripts/prepare_sync_config.py' --output '{{tmp-dir}}/cli-b.edn' --auth-path '{{tmp-dir}}/home/logseq/auth.json' --http-base '{{sync-http-base}}' --ws-url '{{sync-ws-url}}'"])

(def ^:private case-local-resource-markers
  ["{{cli-home}}"
   "{{config-path}}"
   "{{config-path-arg}}"
   "{{tmp-dir}}/cli-b.edn"
   "{{auth-path}}"
   "{{home-dir}}"])

(defn- requires-case-local-resources?
  [command]
  (boolean (some #(string/includes? command %) case-local-resource-markers)))

(defn before-suite!
  [{:keys [run-command sync-port]
    :or {run-command shell/run!
         sync-port default-sync-port}}]
  (let [sync-port (str sync-port)
        suite-tmp-dir (str (fs/create-temp-dir {:prefix "logseq-cli-e2e-sync-suite-"}))
        db-sync-pid-file (str (fs/path suite-tmp-dir "db-sync-server.pid"))
        db-sync-log-file (str (fs/path suite-tmp-dir "db-sync-server.log"))
        db-sync-root-dir (str (fs/path suite-tmp-dir "db-sync-server-data"))
        sync-http-base (str "http://127.0.0.1:" sync-port)
        sync-ws-url (str "ws://127.0.0.1:" sync-port "/sync/%s")
        auth-path (str (fs/path suite-tmp-dir "auth.json"))
        start-db-sync-cmd (format "python3 %s start --repo-root %s --pid-file %s --log-file %s --data-dir %s --port %s --startup-timeout-s 60 --auth-path %s --mint-auth"
                                  (shell-quote (paths/repo-path "cli-e2e" "scripts" "db_sync_server.py"))
                                  (shell-quote (paths/repo-root))
                                  (shell-quote db-sync-pid-file)
                                  (shell-quote db-sync-log-file)
                                  (shell-quote db-sync-root-dir)
                                  sync-port
                                  (shell-quote auth-path))]
    (run-command {:cmd start-db-sync-cmd
                  :dir (paths/repo-root)})
    {:suite-tmp-dir suite-tmp-dir
     :suite-auth-path auth-path
     :db-sync-pid-file db-sync-pid-file
     :db-sync-log-file db-sync-log-file
     :db-sync-root-dir db-sync-root-dir
     :sync-port sync-port
     :sync-http-base sync-http-base
     :sync-ws-url sync-ws-url}))

(defn prepare-case
  [case {:keys [suite-auth-path sync-port sync-http-base sync-ws-url]}]
  (let [setup-commands (vec (:setup case))
        insertion-point? (fn [command]
                           (or (heavy-command? command heavy-setup-patterns)
                               (requires-case-local-resources? command)))
        leading-setup (->> setup-commands
                           (take-while #(not (insertion-point? %)))
                           vec)
        trailing-setup (->> setup-commands
                            (drop (count leading-setup))
                            (remove #(heavy-command? % heavy-setup-patterns))
                            vec)
        cleanup' (->> (:cleanup case)
                      (remove #(heavy-command? % heavy-cleanup-patterns))
                      vec)]
    (-> case
        (update :vars merge {:sync-port sync-port
                             :suite-auth-path suite-auth-path
                             :sync-http-base sync-http-base
                             :sync-ws-url sync-ws-url})
        (assoc :setup (vec (concat leading-setup
                                   (case-local-setup-prefix)
                                   trailing-setup)))
        (assoc :cleanup cleanup'))))

(defn after-suite!
  [{:keys [db-sync-pid-file]}
   {:keys [run-command]
    :or {run-command shell/run!}}]
  (when (and (string? db-sync-pid-file)
             (not (string/blank? db-sync-pid-file)))
    (run-command {:cmd (format "python3 %s stop --pid-file %s"
                               (shell-quote (paths/repo-path "cli-e2e" "scripts" "db_sync_server.py"))
                               (shell-quote db-sync-pid-file))
                  :dir (paths/repo-root)
                  :throw? false})))
