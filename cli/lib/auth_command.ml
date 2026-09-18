open Cli_effect.Infix

type parsed =
  | Parsed_login of {
      username : string option;
      phrase : string option;
      show_phrase : bool;
    }
  | Parsed_logout

type action = Login of Auth_state.login_options | Logout

let command_id = function
  | Parsed_login _ -> Command_id.Login
  | Parsed_logout -> Logout

let validate_parsed = function
  | Parsed_login { username = Some name; _ } when String.trim name = "" ->
      Error (Error.invalid_options "--username requires a non-empty value")
  | Parsed_login { phrase = Some phrase; _ } when String.trim phrase = "" ->
      Error (Error.invalid_options "--phrase requires a non-empty value")
  | Parsed_login _ | Parsed_logout -> Ok ()

let build ?registry:_ _ _ parsed =
  Error.map
    (fun () ->
      match parsed with
      | Parsed_login { username; phrase; show_phrase } ->
          Login { Auth_state.requested_name = username; phrase; show_phrase }
      | Parsed_logout -> Logout)
    (validate_parsed parsed)

let login_value (result : Auth_state.login_result) =
  let fields =
    Vec.of_array
      [|
        (Edn_util.keyword "auth-path", Edn_util.string result.auth_path);
        (Edn_util.keyword "identity-path", Edn_util.string result.identity_path);
        ( Edn_util.keyword "identity-created",
          Edn_util.bool result.identity_created );
        (Edn_util.keyword "address", Edn_util.string result.address);
        (Edn_util.keyword "username", Edn_util.string result.stored_name);
        ( Edn_util.keyword "expires-at",
          Edn_util.int64 (Time.time_to_epoch_ms result.token_expires_at) );
        ( Edn_util.keyword "updated-at",
          Edn_util.int64 (Time.time_to_epoch_ms result.updated_at) );
      |]
  in
  let fields =
    match result.shown_phrase with
    | Some phrase ->
        Vec.push_back fields (Edn_util.keyword "phrase", Edn_util.string phrase)
    | None -> fields
  in
  Edn_util.map_vec fields

let logout_value (result : Auth_state.logout_result) =
  Edn_util.map_vec
    (Vec.of_array
       [|
         (Edn_util.keyword "auth-path", Edn_util.string result.logout_auth_path);
         (Edn_util.keyword "deleted", Edn_util.bool result.deleted);
       |])

let execute_with_mode action config mode =
  match action with
  | Login options -> (
      Auth_state.login config options >>= function
      | Ok result ->
          Cli_effect.pure
            (Cli_result.ok ~command:Command_id.Login mode
               (Raw (login_value result)))
      | Error err ->
          Cli_effect.pure (Output_mode.error ~command:Command_id.Login mode err)
      )
  | Logout -> (
      Auth_state.logout config >>= function
      | Ok result ->
          Cli_effect.pure
            (Cli_result.ok ~command:Command_id.Logout mode
               (Raw (logout_value result)))
      | Error err ->
          Cli_effect.pure
            (Output_mode.error ~command:Command_id.Logout mode err))

let meta id doc =
  {
    Command_registry.id;
    path = Command_id.to_path id;
    doc;
    long_doc = None;
    examples = Vec.empty;
    options = Vec.empty;
    category = Command_registry.Authentication;
    requires_graph = Command_id.requires_graph id;
    requires_auth = Command_id.requires_auth id;
    write_command = Command_id.is_write id;
    human_table_headers_order = Vec.empty;
  }

let metadata () =
  Vec.of_array [| meta Command_id.Login "Login"; meta Logout "Logout" |]

let execute action config =
  let (Output.Mode.Packed mode) = Output_mode.for_config config in
  execute_with_mode action config mode
