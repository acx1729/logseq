open Cli_effect.Infix

let hostname = Cli_unix.gethostname

module Stdout = struct
  type writable

  external stdout : writable = "stdout" [@@mel.module "process"]

  external on_error :
    writable -> (_[@mel.as "error"]) -> ((Js.Exn.t -> unit)[@u]) -> unit = "on"
  [@@mel.send]

  external error_code : Js.Exn.t -> string option = "code"
  [@@mel.get] [@@mel.return { undefined_to_opt }]
end

let stdout_error_handler_installed = ref false

let install_stdout_error_handler () =
  if not !stdout_error_handler_installed then (
    stdout_error_handler_installed := true;
    Stdout.on_error Stdout.stdout (fun[@u] error ->
        match Stdout.error_code error with
        | Some "EPIPE" -> exit 0
        | _ ->
            Js.Exn.raiseError
              (Option.value (Js.Exn.message error) ~default:"JavaScript error")))

let argv () =
  install_stdout_error_handler ();
  Node.Process.argv

module Timer = struct
  let set_timeout f ms = Js.Global.setTimeout ~f ms
  let clear_timeout = Js.Global.clearTimeout
end

module Symbols = struct
  let ellipsis = Js.String.fromCodePoint 0x2026
  let linked_arrow = Js.String.fromCodePoint 0x2192 ^ " "
  let tree_line = Js.String.fromCodePoint 0x2500
  let tree_last = Js.String.fromCodePoint 0x2514 ^ tree_line ^ tree_line ^ " "
  let tree_middle = Js.String.fromCodePoint 0x251c ^ tree_line ^ tree_line ^ " "
  let tree_pipe = Js.String.fromCodePoint 0x2502 ^ "   "
end

module HTTP = struct
  external promise_error_name : Js.Promise.error -> string option = "name"
  [@@mel.get] [@@mel.return { undefined_to_opt }]

  external promise_error_message : Js.Promise.error -> string option = "message"
  [@@mel.get] [@@mel.return { undefined_to_opt }]

  let promise_to_effect ?(on_settle = fun () -> ()) promise =
    let task, resolver = Cli_effect.wait () in
    let finish result =
      if Cli_effect.is_pending task then Cli_effect.wakeup resolver result
    in
    let on_ok value =
      on_settle ();
      finish (Ok value);
      Js.Promise.resolve ()
    in
    let on_error error =
      let message =
        match promise_error_name error with
        | Some "AbortError" -> "request timeout"
        | _ ->
            Option.value
              (promise_error_message error)
              ~default:"JavaScript promise rejected"
      in
      on_settle ();
      finish (Error message);
      Js.Promise.resolve ()
    in
    ignore
      (promise |> Js.Promise.then_ on_ok |> Js.Promise.catch on_error
        : unit Js.Promise.t);
    task >>= function
    | Ok value -> Cli_effect.pure value
    | Error message -> Cli_effect.error (Failure message)

  let timeout_ms = function
    | Some timeout_span when Float.compare timeout_span 0. > 0 ->
        int_of_float timeout_span
    | _ -> 0

  let is_body_forbidden = function Fetch.Get | Fetch.Head -> true | _ -> false

  let request_body method_ body =
    if is_body_forbidden method_ && body <> "" then
      invalid_arg "GET and HEAD requests must not include a body"
    else if body = "" then None
    else Some (Fetch.BodyInit.make body)

  let timeout controller timeout_span =
    match timeout_ms timeout_span with
    | 0 -> None
    | ms ->
        Some
          (Timer.set_timeout
             (fun () -> Fetch.AbortController.abort controller)
             ms)

  let clear_timeout_opt = function
    | None -> ()
    | Some timeout_handle -> Timer.clear_timeout timeout_handle

  let response_text response =
    Fetch.Response.text response
    |> Js.Promise.then_ (fun body -> Js.Promise.resolve (response, body))

  let request ?timeout_span method_ url ~headers ~body =
    let controller = Fetch.AbortController.make () in
    let timeout_handle = timeout controller timeout_span in
    let body = request_body method_ body in
    let init =
      Fetch.RequestInit.make ~method_
        ~headers:(Fetch.HeadersInit.makeWithArray (Rrbvec.to_array headers))
        ?body
        ~signal:(Fetch.AbortController.signal controller)
        ()
    in
    promise_to_effect
      ~on_settle:(fun () -> clear_timeout_opt timeout_handle)
      (Fetch.fetchWithInit url init |> Js.Promise.then_ response_text)
end

module Crypto = struct
  module Node_crypto = struct
    type hash

    external create_hash : string -> hash = "createHash" [@@mel.module "crypto"]
    external update : hash -> string -> string -> hash = "update" [@@mel.send]
    external digest : hash -> string -> string = "digest" [@@mel.send]

    external random_bytes : int -> Node.Buffer.t = "randomBytes"
    [@@mel.module "crypto"]
  end

  let sha256_digest output_encoding text =
    let hash = Node_crypto.create_hash "sha256" in
    let hash = Node_crypto.update hash text "latin1" in
    Node_crypto.digest hash output_encoding

  let sha256_hex text = sha256_digest "hex" text
  let sha256_base64url text = sha256_digest "base64url" text

  let random_base64url size =
    let text =
      Node_crypto.random_bytes size |> Node.Buffer.toString ~encoding:`base64url
    in
    if String.length text <= size then text else String.sub text 0 size

  let base64url_decode text =
    Node.Buffer.fromStringWithEncoding text ~encoding:`base64url
    |> Node.Buffer.toString ~encoding:`utf8
end

module Events = struct
  type subscription = { close : unit -> unit Cli_effect.t }
  type readable_stream
  type reader
  type read_result
  type text_decoder
  type uint8_array

  external response_body : Fetch.Response.t -> readable_stream option = "body"
  [@@mel.get] [@@mel.return { null_to_opt }]

  external get_reader : readable_stream -> reader = "getReader" [@@mel.send]
  external read : reader -> read_result Js.Promise.t = "read" [@@mel.send]
  external cancel : reader -> unit Js.Promise.t = "cancel" [@@mel.send]
  external read_done : read_result -> bool = "done" [@@mel.get]

  external read_value : read_result -> uint8_array option = "value"
  [@@mel.get] [@@mel.return { undefined_to_opt }]

  external make_decoder : unit -> text_decoder = "TextDecoder" [@@mel.new]

  external decode :
    text_decoder -> uint8_array -> < stream : bool > Js.t -> string = "decode"
  [@@mel.send]

  let stream_options =
    let options = Js.Obj.empty () in
    Js.Obj.assign options [%obj { stream = true }]

  let rec read_loop closed decoder reader on_chunk =
    if !closed then Js.Promise.resolve ()
    else
      read reader
      |> Js.Promise.then_ (fun result ->
          if !closed || read_done result then Js.Promise.resolve ()
          else (
            result |> read_value
            |> Option.iter (fun value ->
                on_chunk (decode decoder value stream_options));
            read_loop closed decoder reader on_chunk))

  let connect ~url ~on_chunk =
    let closed = ref false in
    let reader_ref = ref None in
    let controller = Fetch.AbortController.make () in
    let init =
      Fetch.RequestInit.make ~method_:Fetch.Get
        ~headers:
          (Fetch.HeadersInit.makeWithArray
             [| ("Accept", "text/event-stream") |])
        ~signal:(Fetch.AbortController.signal controller)
        ()
    in
    Cli_effect.bind
      (HTTP.promise_to_effect (Fetch.fetchWithInit url init))
      (fun response ->
        if not (Fetch.Response.ok response) then
          Cli_effect.error
            (Js.Exn.raiseError
               ("events request failed ("
               ^ string_of_int (Fetch.Response.status response)
               ^ ")"))
        else
          let request =
            (match response_body response with
              | None ->
                  Fetch.Response.text response
                  |> Js.Promise.then_ (fun text ->
                      if not !closed then on_chunk text;
                      Js.Promise.resolve ())
              | Some body ->
                  let reader = get_reader body in
                  reader_ref := Some reader;
                  read_loop closed (make_decoder ()) reader on_chunk)
            |> Js.Promise.catch (fun _ -> Js.Promise.resolve ())
          in
          let close () =
            Fetch.AbortController.abort controller;
            (match !reader_ref with
            | None -> ()
            | Some reader ->
                ignore
                  (cancel reader
                   |> Js.Promise.catch (fun _ -> Js.Promise.resolve ())
                    : unit Js.Promise.t));
            Cli_effect.catch (HTTP.promise_to_effect request) (fun _ ->
                Cli_effect.pure ())
          in
          Cli_effect.pure { close })
end
