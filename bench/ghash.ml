open Nocrypto
open Uncommon
open Cipher_block

let _ = Nocrypto_entropy_unix.initialize ()

let () =
  let fd = Unix.(openfile Sys.argv.(1) [O_RDONLY] 0) in
  let cs = Unix_cstruct.of_fd fd in
  let t0   = Unix.gettimeofday () in
  let key = AES.GCM.of_secret (Cs.of_hex "0001020304050607 08090a0b0c0d0e0f") in
  let t1   = Unix.gettimeofday () in
  let iv  = Cs.of_hex "000102030405060708090a0b" in
  let hash = AES.GCM.encrypt ~key ~iv ~adata:cs Cs.empty in
  let t2   = Unix.gettimeofday () in
  Format.printf "time: @[<v>derive: %.06f@,ghash:  %.04f@]\n%a\n%!"
    (t1 -. t0) (t2 -. t1) (xd ~ascii:true()) hash.AES.GCM.tag
