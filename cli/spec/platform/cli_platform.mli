val hostname : unit -> string
val argv : unit -> string array

module Symbols : sig
  val ellipsis : string
  val linked_arrow : string
  val tree_last : string
  val tree_middle : string
  val tree_pipe : string
end

module HTTP : sig
  val request :
    ?timeout_span:float ->
    Fetch.requestMethod ->
    string ->
    headers:(string * string) Rrbvec.t ->
    body:string ->
    (Fetch.Response.t * string) Cli_effect.t
end

module Crypto : sig
  val sha256_hex : string -> string
  val sha256_base64url : string -> string
  val random_base64url : int -> string
  val base64url_decode : string -> string
end

module Events : sig
  type subscription = { close : unit -> unit Cli_effect.t }

  val connect :
    url:string -> on_chunk:(string -> unit) -> subscription Cli_effect.t
end
