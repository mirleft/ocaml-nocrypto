
open Lwt
open Nocrypto


let time f =
  let t1 = Sys.time () in
  let r  = f () in
  let t2 = Sys.time () in
  Printf.printf "[time] %.04f sec\n%!" (t2 -. t1) ;
  r

let rec replicate f = function
  | 0 -> []
  | n -> let x = f () in x :: replicate f (pred n)

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

open Nocrypto


let on_stdin fn =
  lwt input = Lwt_io.(read stdin) in
  let res = fn (Cstruct.of_string input) in
  let b   = Buffer.create 16 in
  Cstruct.hexdump_to_buffer b res;
  Lwt_io.printl (Buffer.contents b)

(* let aes_key str = Block.AES.of_secret (Cstruct.of_string str) *)

let main () =
  match List.tl (Array.to_list Sys.argv) with

  | ["md5"]       -> on_stdin Hash.MD5.digest

  | ["sha1"]      -> on_stdin Hash.SHA1.digest

  | ["hmac_md5" ; k] -> on_stdin @@ Hash.MD5.hmac ~key:(cs_of_s k)

  | ["hmac_sha1"; k] -> on_stdin @@ Hash.SHA1.hmac ~key:(cs_of_s k)

(*   | ["aes_ecb"; "encrypt"; k] -> on_stdin Block.AES.(encrypt_ecb ~key:(aes_key k))

  | ["aes_ecb"; "decrypt"; k] -> on_stdin Block.AES.(decrypt_ecb ~key:(aes_key k))

  | ["aes_cbc"; "encrypt"; k; iv] -> on_stdin @@ fun i ->
      snd Block.AES.(encrypt_cbc ~key:(aes_key k) ~iv:(cs_of_s iv) i)

  | ["aes_cbc"; "decrypt"; k; iv] -> on_stdin @@ fun i ->
      snd Block.AES.(decrypt_cbc ~key:(aes_key k) ~iv:(cs_of_s iv) i) *)

  | _ ->
      Printf.eprintf
        "%s: [ md5 | sha1 | hmac_md5 <key> | hmac_sha1 <key> ]\n%!"
        Sys.argv.(0);
      exit 1

(* let () = Lwt_main.run @@ main () *)

(* let () =

  let pt  = Cstruct.of_string "<(^_^<)  (>^_^)>"
  and iv  = Cstruct.of_string "desu1234desu1234"
  and key = AES.of_secret (Cstruct.of_string "aaaabbbbccccdddd") in
  let pts = time @@ fun () ->
    cs_concat @@ replicate (fun () -> pt ) 100000 in
  let _ = time @@ fun () ->
    AES.encrypt_cbc key iv pts
  and _ = time @@ fun () ->
    AES.encrypt_cbc' key iv pts
  in
  () *)

(* let () =
  let g = Fortuna.create () in
  Fortuna.reseed g (Cstruct.of_string "\001\002\003\004");
  let _ = time @@ fun () ->
    for i = 1 to 10 do
      ignore @@ Fortuna.generate g (int_of_float @@ 10. *. (2.**20.))
    done in
  () *)

(* let () =
  Rng.reseed (Cstruct.of_string "\001\002\003\004");
  let _ = time @@ fun () ->
    for i = 1 to 1000000 do
      ignore @@ Rng.Rng.Int.gen 0x2000000000000001
    done in
  () *)

(* let () =
  Rng.reseed (Cstruct.of_string "\001\002\003\004");
  let items = 10000000 in
  let cs    = time @@ fun () -> Rng.generate (items * 8) in
  time @@ fun () ->
    let rec loop cs = function
      | 0 -> ()
      | n ->
          ignore (Numeric.Z.of_bits_be cs (7 * 8 + 3));
          loop (Cstruct.shift cs 8) (pred n) in
    loop cs items *)

let () =
  Rng.reseed (Cstruct.of_string "\001\002\003\004");
  let items = 100 in
  time @@ fun () ->
    for i = 1 to items do
      ignore @@ Nocrypto.Rsa.generate 2048
    done
