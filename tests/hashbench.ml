
open Nocrypto.Hash

let time ?(label = "time") f =
  let t1 = Sys.time () in
  let r  = f () in
  let t2 = Sys.time () in
  Printf.printf "[%s] %.04f sec\n%!" label (t2 -. t1) ;
  r


let md5    = (module MD5    : T)
let sha1   = (module SHA1   : T)
let sha224 = (module SHA224 : T)
let sha256 = (module SHA256 : T)
let sha384 = (module SHA384 : T)
let sha512 = (module SHA512 : T)
let hashes = [
  "md5"   , md5    ;
  "sha1"  , sha1   ;
  "sha224", sha224 ;
  "sha256", sha256 ;
  "sha384", sha384 ;
  "sha512", sha512
  ]

let mmap path =
  Unix_cstruct.of_fd Unix.(openfile path [O_RDONLY] 0)

let run path = 
  let cs = mmap path in
  time ~label:"total" @@ fun () ->
    hashes |> List.iter @@ fun (label, h) ->
      let module H = (val h : T) in
      time ~label @@ fun () -> ignore @@ H.digest cs

let _ = run Sys.argv.(1)

(*
  [md5]    2.4333 sec
  [sha1]   3.6667 sec
  [sha224] 5.0333 sec
  [sha256] 5.0333 sec
  [sha384] 3.2900 sec
  [sha512] 3.2900 sec
  [total] 22.7466 sec
*) 
