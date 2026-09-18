(* The identity the CLI signs in with: a BIP-39 recovery phrase from which the
   secp256k1 key and Ethereum address derive. Phrases are generated and checked
   with @scure/bip39; messages are signed with viem, the library the sync
   server verifies with. *)

type t = { phrase : string; address : string }
type wordlist
type account

external english_wordlist : wordlist = "wordlist"
[@@mel.module "@scure/bip39/wordlists/english"]

external generate_mnemonic : wordlist -> string = "generateMnemonic"
[@@mel.module "@scure/bip39"]

external validate_mnemonic : string -> wordlist -> bool = "validateMnemonic"
[@@mel.module "@scure/bip39"]

external mnemonic_to_account : string -> account = "mnemonicToAccount"
[@@mel.module "viem/accounts"]

external account_address : account -> string = "address" [@@mel.get]

external account_sign_message :
  account -> < message : string > Js.t -> string Js.Promise.t = "signMessage"
[@@mel.send]

external create_siwe_message :
  < address : string
  ; chainId : int
  ; domain : string
  ; nonce : string
  ; uri : string
  ; version : string
  ; statement : string
  ; issuedAt : Js.Date.t
  ; expirationTime : Js.Date.t >
  Js.t ->
  string = "createSiweMessage"
[@@mel.module "viem/siwe"]

external promise_error_message : Js.Promise.error -> string option = "message"
[@@mel.get] [@@mel.return { undefined_to_opt }]

let normalize_phrase phrase =
  String.lowercase_ascii phrase
  |> String.split_on_char ' '
  |> List.concat_map (String.split_on_char '\n')
  |> List.concat_map (String.split_on_char '\r')
  |> List.concat_map (String.split_on_char '\t')
  |> List.filter (fun word -> word <> "")
  |> String.concat " "

let invalid_phrase () =
  Error.make
    ~hint:"Pass the words of a recovery phrase separated by spaces."
    Error.Invalid_phrase "recovery phrase is not a valid BIP-39 phrase"

let of_phrase phrase =
  let phrase = normalize_phrase phrase in
  if phrase = "" || not (validate_mnemonic phrase english_wordlist) then
    Error (invalid_phrase ())
  else
    let account = mnemonic_to_account phrase in
    Ok { phrase; address = account_address account }

let generate () =
  match of_phrase (generate_mnemonic english_wordlist) with
  | Ok identity -> identity
  | Error err -> failwith ("generated phrase was refused: " ^ err.Error.message)

let same left right =
  String.lowercase_ascii left.address = String.lowercase_ascii right.address

let siwe_message ~address ~chain_id ~domain ~uri ~nonce ~statement ~issued_at
    ~expiration_time =
  create_siwe_message
    [%obj
      {
        address;
        chainId = chain_id;
        domain;
        nonce;
        uri;
        version = "1";
        statement;
        issuedAt = issued_at;
        expirationTime = expiration_time;
      }]

let effect_of_promise promise =
  let task, resolver = Cli_effect.wait () in
  ignore
    (promise
     |> Js.Promise.then_ (fun value ->
            Cli_effect.wakeup resolver (Ok value);
            Js.Promise.resolve ())
     |> Js.Promise.catch (fun error ->
            Cli_effect.wakeup resolver
              (Error
                 (Option.value
                    (promise_error_message error)
                    ~default:"signing failed"));
            Js.Promise.resolve ())
      : unit Js.Promise.t);
  Cli_effect.bind task (function
    | Ok value -> Cli_effect.pure value
    | Error message -> Cli_effect.error (Failure message))

let sign identity message =
  let account = mnemonic_to_account identity.phrase in
  effect_of_promise (account_sign_message account [%obj { message }])
