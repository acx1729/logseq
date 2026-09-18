open Cli_effect.Infix

type auth_data = {
  access_token : string;
  sub : string;
  username : string;
  expires_at : Js.Date.t;
  updated_at : Js.Date.t;
}

type login_options = {
  requested_name : string option;
  phrase : string option;
  show_phrase : bool;
}

type login_result = {
  auth_path : Cli_primitive.path;
  identity_path : Cli_primitive.path;
  identity_created : bool;
  address : string;
  stored_name : string;
  token_expires_at : Js.Date.t;
  updated_at : Js.Date.t;
  shown_phrase : string option;
}

type logout_result = { logout_auth_path : Cli_primitive.path; deleted : bool }

let home_dir () = Sys.getenv_opt "HOME" |> Option.value ~default:"."
let logseq_dir () = Filename.concat (home_dir ()) "logseq"
let default_auth_path () = Filename.concat (logseq_dir ()) "auth.json"
let default_identity_path () = Filename.concat (logseq_dir ()) "identity.json"

let auth_path config =
  Option.value config.Cli_config.auth_path ~default:(default_auth_path ())

let identity_path config =
  Option.value config.Cli_config.identity_path
    ~default:(default_identity_path ())

let read_file = Cli_unix.read_text_file

let path_context key path =
  Edn_util.map_vec
    (Vec.of_array [| (Edn_util.keyword key, Edn_util.string path) |])

let auth_path_context path = path_context "auth-path" path
let identity_path_context path = path_context "identity-path" path

let nonempty_string_field object_ key =
  match Json_util.string_field object_ key with
  | Some value when String.trim value <> "" -> Some value
  | _ -> None

(* Tokens *)

let jwt_payload token =
  let parts = Vec.split_on_char '.' token in
  if Vec.length parts = 3 then
    Ok (Cli_platform.Crypto.base64url_decode (Vec.nth parts 1))
  else Error (Error.make Error.Invalid_auth_token "invalid auth token")

let invalid_token message = Error.make Error.Invalid_auth_token message

(* The claims a session token carries: the address, the display name on file
   and the expiry the sync server minted. *)
let token_claims token =
  Error.bind (jwt_payload token) (fun payload ->
      let claims = try Json_util.object_of_json_string payload with _ -> None in
      match claims with
      | None -> Error (invalid_token "auth token payload is not a JSON object")
      | Some claims -> (
          match
            ( nonempty_string_field claims "sub",
              nonempty_string_field claims "username",
              Json_util.number_field claims "exp" )
          with
          | Some sub, Some username, Some exp
            when Json_util.is_integral_float exp
                 && exp > 0.
                 && exp <= Time.time_to_epoch_seconds_float Time.max_time ->
              Ok (sub, username, Time.time_of_epoch_ms_float (exp *. 1000.))
          | _ ->
              Error (invalid_token "auth token lacks sub, username or exp claims")
          ))

let auth_of_token ~updated_at token =
  Error.map
    (fun (sub, username, expires_at) ->
      { access_token = token; sub; username; expires_at; updated_at })
    (token_claims token)

let expired_auth auth = Time.compare_time auth.expires_at (Time.now ()) <= 0

(* Auth file: the token alone, as every client writes it. *)

let auth_json data =
  let object_ = Js.Dict.empty () in
  Js.Dict.set object_ "access-token" (Js.Json.string data.access_token);
  Js.Dict.set object_ "updated-at"
    (Js.Json.number (Int64.to_float (Time.time_to_epoch_ms data.updated_at)));
  Js.Json.stringify (Js.Json.object_ object_) ^ "\n"

let parse_auth_json text =
  match Json_util.object_of_json_string text with
  | None -> Error (Error.make Error.Invalid_auth_file "invalid auth file")
  | Some object_ -> (
      match nonempty_string_field object_ "access-token" with
      | None ->
          Error (Error.make Error.Invalid_auth_file "auth file has no access-token")
      | Some token ->
          let updated_at =
            match Json_util.int64_field object_ "updated-at" with
            | Some ms -> Time.time_of_epoch_ms ms
            | None -> Time.epoch
          in
          auth_of_token ~updated_at token)

let read_auth_file config =
  let path = auth_path config in
  Cli_effect.pure
    (if not (Cli_unix.file_exists path) then Ok None
     else
       try Error.map (fun data -> Some data) (parse_auth_json (read_file path))
       with exn ->
         Error
           (Error.make ~context:(auth_path_context path) Error.Invalid_auth_file
              (Printexc.to_string exn)))

let write_auth_file config data =
  let path = auth_path config in
  Cli_effect.pure
    (try
       Cli_unix.mkdir_p (Filename.dirname path);
       Cli_unix.write_text_file path (auth_json data);
       (try Cli_unix.chmod path 0o600 with Cli_unix.Cli_unix_error _ -> ());
       Ok data
     with exn ->
       Error
         (Error.make ~context:(auth_path_context path)
            Error.Auth_file_write_failed (Printexc.to_string exn)))

let delete_auth_file config =
  let path = auth_path config in
  Cli_effect.pure
    (try
       if Cli_unix.file_exists path then Cli_unix.remove_tree path;
       Ok ()
     with exn ->
       Error
         (Error.make ~context:(auth_path_context path)
            Error.Auth_file_delete_failed (Printexc.to_string exn)))

let missing_auth config message =
  Error.make ~hint:"Run `logseq login` first."
    ~context:(auth_path_context (auth_path config))
    Error.Missing_auth message

(* Identity file: the recovery phrase and the address it derives to. *)

let identity_json (identity : Wallet_identity.t) =
  let object_ = Js.Dict.empty () in
  Js.Dict.set object_ "phrase" (Js.Json.string identity.Wallet_identity.phrase);
  Js.Dict.set object_ "address"
    (Js.Json.string identity.Wallet_identity.address);
  Js.Json.stringify (Js.Json.object_ object_) ^ "\n"

let invalid_identity_file path message =
  Error.make ~context:(identity_path_context path) Error.Invalid_identity_file
    message

let parse_identity_json path text =
  match Json_util.object_of_json_string text with
  | None -> Error (invalid_identity_file path "invalid identity file")
  | Some object_ -> (
      match
        ( nonempty_string_field object_ "phrase",
          nonempty_string_field object_ "address" )
      with
      | Some phrase, Some address -> (
          match Wallet_identity.of_phrase phrase with
          | Error _ ->
              Error
                (invalid_identity_file path
                   "identity file phrase is not a valid recovery phrase")
          | Ok identity ->
              if
                String.lowercase_ascii identity.Wallet_identity.address
                = String.lowercase_ascii address
              then Ok identity
              else
                Error
                  (invalid_identity_file path
                     "identity file address does not match its phrase"))
      | _ ->
          Error (invalid_identity_file path "identity file needs phrase and address"))

let read_identity_file config =
  let path = identity_path config in
  Cli_effect.pure
    (if not (Cli_unix.file_exists path) then Ok None
     else
       try
         Error.map
           (fun identity -> Some identity)
           (parse_identity_json path (read_file path))
       with exn -> Error (invalid_identity_file path (Printexc.to_string exn)))

let write_identity_file config (identity : Wallet_identity.t) =
  let path = identity_path config in
  Cli_effect.pure
    (try
       Cli_unix.mkdir_p (Filename.dirname path);
       Cli_unix.write_text_file path (identity_json identity);
       (try Cli_unix.chmod path 0o600 with Cli_unix.Cli_unix_error _ -> ());
       Ok identity
     with exn ->
       Error
         (Error.make ~context:(identity_path_context path)
            Error.Identity_file_write_failed (Printexc.to_string exn)))

(* Sign-in against the sync server *)

let normalize_base_url value =
  let value = String.trim value in
  if value <> "" && value.[String.length value - 1] = '/' then
    String.sub value 0 (String.length value - 1)
  else value

let http_base config =
  match config.Cli_config.http_base with
  | Some base when String.trim base <> "" -> Ok (normalize_base_url base)
  | _ ->
      Error
        (Error.make
           ~hint:
             "Set :http-base in cli.edn (or LOGSEQ_CLI_HTTP_BASE) to the sync \
              server address."
           Error.Missing_http_base "sync server address is not configured")

let http_error_message status body =
  if String.trim body = "" then
    "http request failed (" ^ string_of_int status ^ ")"
  else
    "http request failed (" ^ string_of_int status ^ ")\nhttp response: " ^ body

let http_request ~(method_ : Fetch.requestMethod) ~url ~headers ~body
    ~timeout_span =
  Cli_platform.HTTP.request ?timeout_span method_ url ~headers ~body
  >>= fun (response, body) ->
  let status = Fetch.Response.status response in
  if status >= 200 && status <= 299 then Cli_effect.pure body
  else Cli_effect.error (Failure (http_error_message status body))

let exn_message = function
  | Failure message -> message
  | exn -> Printexc.to_string exn

let sign_in_failed ~step exn =
  Error.make ~hint:"Check :http-base and that the sync server is running."
    ~context:
      (Edn_util.map_vec
         (Vec.of_array
            [|
              (Edn_util.keyword "step", Edn_util.string step);
              (Edn_util.keyword "error", Edn_util.string (exn_message exn));
            |]))
    Error.Sign_in_failed ("sign-in failed during " ^ step)

let get_json config ~url ~step =
  Cli_effect.catch
    (Cli_effect.map
       (fun body -> Ok body)
       (http_request ~method_:Fetch.Get ~url
          ~headers:(Vec.singleton ("Accept", "application/json"))
          ~body:"" ~timeout_span:(Some config.Cli_config.timeout_span)))
    (fun exn -> Cli_effect.pure (Error (sign_in_failed ~step exn)))

let post_json config ~url ~body ~step =
  Cli_effect.catch
    (Cli_effect.map
       (fun body -> Ok body)
       (http_request ~method_:Fetch.Post ~url
          ~headers:
            (Vec.of_array
               [|
                 ("Content-Type", "application/json");
                 ("Accept", "application/json");
               |])
          ~body ~timeout_span:(Some config.Cli_config.timeout_span)))
    (fun exn -> Cli_effect.pure (Error (sign_in_failed ~step exn)))

type client_config = { issuer : string; chain_id : int; statement : string }

let invalid_response step message =
  Error.make Error.Sign_in_failed ("sync server " ^ step ^ " " ^ message)

let json_object step body =
  let parsed = try Json_util.object_of_json_string body with _ -> None in
  match parsed with
  | Some object_ -> Ok object_
  | None -> Error (invalid_response step "response is not a JSON object")

(* The first accepted chain id is the one the CLI signs on. *)
let client_config_of_body body =
  Error.bind (json_object "/auth/config" body) (fun object_ ->
      let chain_id =
        match
          Option.bind (Json_util.field object_ "chain_ids") Js.Json.decodeArray
        with
        | Some values when Array.length values > 0 ->
            Option.map int_of_float (Js.Json.decodeNumber values.(0))
        | _ -> None
      in
      match
        ( nonempty_string_field object_ "issuer",
          chain_id,
          nonempty_string_field object_ "statement" )
      with
      | Some issuer, Some chain_id, Some statement ->
          Ok { issuer; chain_id; statement }
      | _ ->
          Error
            (invalid_response "/auth/config"
               "response lacks issuer, chain_ids or statement"))

let nonce_of_body body =
  Error.bind (json_object "/auth/nonce" body) (fun object_ ->
      match nonempty_string_field object_ "nonce" with
      | Some nonce -> Ok nonce
      | None -> Error (invalid_response "/auth/nonce" "response lacks nonce"))

let token_of_body body =
  Error.bind (json_object "/auth/siwe" body) (fun object_ ->
      match nonempty_string_field object_ "access_token" with
      | Some token -> auth_of_token ~updated_at:(Time.now ()) token
      | None ->
          Error (invalid_response "/auth/siwe" "response lacks access_token"))

type url

external make_url : string -> url = "URL" [@@mel.new]
external url_host : url -> string = "host" [@@mel.get]

(* Desktop, mobile and CLI clients name the issuer as the message domain. *)
let issuer_host issuer =
  let host = try Some (url_host (make_url issuer)) with _ -> None in
  match host with
  | Some host when host <> "" -> Ok host
  | _ ->
      Error
        (invalid_response "/auth/config" ("issuer is not a URL: " ^ issuer))

let siwe_body ~message ~signature ~display_name =
  let object_ = Js.Dict.empty () in
  Js.Dict.set object_ "message" (Js.Json.string message);
  Js.Dict.set object_ "signature" (Js.Json.string signature);
  Option.iter
    (fun name -> Js.Dict.set object_ "username" (Js.Json.string name))
    display_name;
  Js.Json.stringify (Js.Json.object_ object_)

let message_lifetime = Time.span_of_ms 300_000L

let sign_in config (identity : Wallet_identity.t) ~display_name =
  match http_base config with
  | Error err -> Cli_effect.pure (Error err)
  | Ok base -> (
      get_json config ~url:(base ^ "/auth/config") ~step:"GET /auth/config"
      >>= function
      | Error err -> Cli_effect.pure (Error err)
      | Ok config_body -> (
          match
            Error.bind (client_config_of_body config_body) (fun client ->
                Error.map (fun host -> (client, host)) (issuer_host client.issuer))
          with
          | Error err -> Cli_effect.pure (Error err)
          | Ok (client, domain) -> (
              get_json config ~url:(base ^ "/auth/nonce") ~step:"GET /auth/nonce"
              >>= function
              | Error err -> Cli_effect.pure (Error err)
              | Ok nonce_body -> (
                  match nonce_of_body nonce_body with
                  | Error err -> Cli_effect.pure (Error err)
                  | Ok nonce -> (
                      let issued_at = Time.now () in
                      let expiration_time =
                        Option.get (Time.add_span issued_at message_lifetime)
                      in
                      let message =
                        Wallet_identity.siwe_message
                          ~address:identity.Wallet_identity.address
                          ~chain_id:client.chain_id ~domain ~uri:client.issuer
                          ~nonce ~statement:client.statement ~issued_at
                          ~expiration_time
                      in
                      Cli_effect.catch
                        (Cli_effect.map
                           (fun signature -> Ok signature)
                           (Wallet_identity.sign identity message))
                        (fun exn ->
                          Cli_effect.pure
                            (Error (sign_in_failed ~step:"signing" exn)))
                      >>= function
                      | Error err -> Cli_effect.pure (Error err)
                      | Ok signature -> (
                          post_json config ~url:(base ^ "/auth/siwe")
                            ~body:(siwe_body ~message ~signature ~display_name)
                            ~step:"POST /auth/siwe"
                          >>= function
                          | Error err -> Cli_effect.pure (Error err)
                          | Ok token_body ->
                              Cli_effect.pure (token_of_body token_body)))))))

(* The token on file when it is still valid; otherwise a fresh sign-in with
   the identity on file, which sync commands rely on instead of refresh
   tokens. *)
let resolve_auth config =
  read_auth_file config >>= function
  | Error err -> Cli_effect.pure (Error err)
  | Ok (Some auth) when not (expired_auth auth) -> Cli_effect.pure (Ok auth)
  | Ok stale -> (
      read_identity_file config >>= function
      | Error err -> Cli_effect.pure (Error err)
      | Ok None ->
          Cli_effect.pure
            (Error
               (missing_auth config
                  (match stale with
                  | None -> "missing auth"
                  | Some _ -> "auth token expired")))
      | Ok (Some identity) -> (
          sign_in config identity ~display_name:None >>= function
          | Error err -> Cli_effect.pure (Error err)
          | Ok auth -> write_auth_file config auth))

let identity_exists config (identity : Wallet_identity.t) =
  Error.make
    ~hint:
      ("Remove " ^ identity_path config
     ^ " to replace the identity on this machine.")
    ~context:
      (Edn_util.map_vec
         (Vec.of_array
            [|
              ( Edn_util.keyword "identity-path",
                Edn_util.string (identity_path config) );
              ( Edn_util.keyword "address",
                Edn_util.string identity.Wallet_identity.address );
            |]))
    Error.Identity_exists
    "an identity with a different address already exists on this machine"

let login config (options : login_options) =
  read_identity_file config >>= function
  | Error err -> Cli_effect.pure (Error err)
  | Ok existing -> (
      let chosen =
        match (options.phrase, existing) with
        | None, Some identity -> Ok (identity, false)
        | None, None -> Ok (Wallet_identity.generate (), true)
        | Some phrase, None ->
            Error.map
              (fun identity -> (identity, true))
              (Wallet_identity.of_phrase phrase)
        | Some phrase, Some identity ->
            Error.bind (Wallet_identity.of_phrase phrase) (fun imported ->
                if Wallet_identity.same imported identity then
                  Ok (identity, false)
                else Error (identity_exists config identity))
      in
      match chosen with
      | Error err -> Cli_effect.pure (Error err)
      | Ok (identity, created) -> (
          (if created then write_identity_file config identity
           else Cli_effect.pure (Ok identity))
          >>= function
          | Error err -> Cli_effect.pure (Error err)
          | Ok identity -> (
              sign_in config identity ~display_name:options.requested_name
              >>= function
              | Error err -> Cli_effect.pure (Error err)
              | Ok auth -> (
                  write_auth_file config auth >>= function
                  | Error err -> Cli_effect.pure (Error err)
                  | Ok (auth : auth_data) ->
                      Cli_effect.pure
                        (Ok
                           ({
                              auth_path = auth_path config;
                              identity_path = identity_path config;
                              identity_created = created;
                              address = identity.Wallet_identity.address;
                              stored_name = auth.username;
                              token_expires_at = auth.expires_at;
                              updated_at = auth.updated_at;
                              shown_phrase =
                                (if options.show_phrase then
                                   Some identity.Wallet_identity.phrase
                                 else None);
                            }
                             : login_result))))))

let logout config =
  let path = auth_path config in
  let existed = Cli_unix.file_exists path in
  delete_auth_file config >>= function
  | Error err -> Cli_effect.pure (Error err)
  | Ok () ->
      Cli_effect.pure
        (Ok ({ logout_auth_path = path; deleted = existed } : logout_result))
