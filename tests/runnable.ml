
open Lwt
open Nocrypto.Core

(*

let random_string () =
  let len = Random.int 1024 in
  let str = String.create len in
  for i = 0 to len - 1 do
    str.[i] <- char_of_int (Random.int 256)
  done;
  str

let head_to_head () =
  let key = random_string ()
  and msg = random_string () in
  let h1 =
    Cstruct.of_string
      Cryptokit.(hash_string (MAC.hmac_sha1 key) msg)
  and h2 =
    Hmac.sha1 ~key:(Cstruct.of_string key)
                   (Cstruct.of_string msg) in
  h1 = h2

let () =
  let cs  = Cstruct.of_string "desu"
  and key = Cstruct.of_string "sekrit" in
  Cstruct.hexdump (Hash.sha1 cs);
  Cstruct.hexdump (Hash.md5 cs);
  Cstruct.hexdump (Hmac.sha1 ~key cs);
  Cstruct.hexdump (Hmac.md5 ~key cs);

*)


let on_stdin fn =
  lwt input = Lwt_io.(read stdin) in
  let res = fn (Cstruct.of_string input) in
  let b   = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b res;
  Lwt_io.printl (Buffer.contents b)

let main () =
  try
    match Sys.argv.(1) with
    | "md5"       -> on_stdin Hash.md5
    | "sha1"      -> on_stdin Hash.sha1
    | "hmac_md5"  -> on_stdin (Hmac.md5  ~key:(Cstruct.of_string Sys.argv.(2)))
    | "hmac_sha1" -> on_stdin (Hmac.sha1 ~key:(Cstruct.of_string Sys.argv.(2)))
    | _           -> invalid_arg "args"
  with Invalid_argument _ ->
    Printf.eprintf
      "%s: [ md5 | sha1 | hmac_md5 <key> | hmac_sha1 <key> ]\n%!"
      Sys.argv.(0);
    exit 1

let () =
  Lwt_main.run @@ main ()

