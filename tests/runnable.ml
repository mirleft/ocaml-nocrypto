
open Lwt
open Nocrypto

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

let cs_of_s = Cstruct.of_string

let on_stdin fn =
  lwt input = Lwt_io.(read stdin) in
  let res = fn (Cstruct.of_string input) in
  let b   = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b res;
  Lwt_io.printl (Buffer.contents b)

let aes_key str = AES.of_secret (Cstruct.of_string str)

let main () =
  match List.tl (Array.to_list Sys.argv) with

  | ["md5"]       -> on_stdin Hash.md5

  | ["sha1"]      -> on_stdin Hash.sha1

  | ["hmac_md5" ; k] -> on_stdin @@ Hmac.md5  ~key:(cs_of_s k)

  | ["hmac_sha1"; k] -> on_stdin @@ Hmac.sha1 ~key:(cs_of_s k)

  | ["aes"; "encrypt"; k] -> on_stdin AES.(encrypt @@ of_secret (cs_of_s k))

  | ["aes"; "decrypt"; k] -> on_stdin AES.(decrypt @@ of_secret (cs_of_s k))

  | ["aes_ecb"; "encrypt"; k] -> on_stdin AES.(encrypt_ecb @@ aes_key k)

  | ["aes_ecb"; "decrypt"; k] -> on_stdin AES.(decrypt_ecb @@ aes_key k)

  | ["aes_cbc"; "encrypt"; k; iv] -> on_stdin @@ fun i ->
      snd AES.(encrypt_cbc (aes_key k) (cs_of_s iv) i)

  | ["aes_cbc"; "decrypt"; k; iv] -> on_stdin @@ fun i ->
      snd AES.(decrypt_cbc (aes_key k) (cs_of_s iv) i)

  | _ ->
      Printf.eprintf
        "%s: [ md5 | sha1 | hmac_md5 <key> | hmac_sha1 <key> ]\n%!"
        Sys.argv.(0);
      exit 1

let () = Lwt_main.run @@ main ()

