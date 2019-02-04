open Nocrypto

let _ = Nocrypto_entropy_unix.initialize ()
(* let _ = Unmark.warmup () *)

let pow x e =
  let rec go acc x = function
    | 0 -> acc
    | e -> if e mod 2 = 0 then go acc (x * x) (e / 2) else go (acc * x) x (e - 1)
  in go 1 x e

let rec (--) a b = if a <= b then a :: succ a -- b else []

let hashes : ((module Hash.S) * string) list = [
  (module Hash.MD5), "md5";
  (module Hash.SHA1), "sha1";
  (module Hash.SHA256), "sha256";
]

(* let t1 _ = *)
(*   let measure = `Cputime in *)
(*   let chunk = 150 in *)
(*   for k = 2 to 4 do *)
(*     let size = pow 15 k in *)
(*     let chain = 1 -- size |> List.map (fun _ -> Rng.generate chunk) in *)
(*     hashes |> List.iter @@ fun (h, name) -> *)
(*       let module H = (val h : Hash.S) in *)
(*       let tag = Fmt.strf "%s @@ %d * %d" name chunk size in *)
(*       let rec go t = function *)
(*           []    -> H.get t *)
(*         | x::xs -> go (H.feed t x; t) xs in *)
(*       Unmark.time ~measure ~n:100 ~tag @@ fun () -> go H.(init()) chain *)
(*   done *)

let t2 _ =
  let measure = `Cputime_ns in
  for _ = 1 to 10 do
    let key = Rsa.generate 2048 in
    let s   = Rsa.encrypt ~key:(Rsa.pub_of_priv key) (Rng.generate 100) in
    Unmark.time ~measure ~n:100 ~tag:"rsa" @@ fun () ->
      Rsa.decrypt ~mask:`No ~key s |> ignore
  done

let t3 _ =
  Rng.Int32.gen_bits (max_int / 2) |> ignore

let seed = Cstruct.of_string "abcdef"

let t4 _ =
  Rng.reseed seed;
  Rng.reseed seed;
  (* let g = Rng.create ~seed (module Rng.Generators.Fortuna) in *)
  Rng.generate 2 |> Cstruct.hexdump;
  Rng.generate 20 |> Cstruct.hexdump;
  Rng.generate 2 |> Cstruct.hexdump;
  Rng.generate 19 |> Cstruct.hexdump;
  for _ = 0 to 10000 do Rng.generate 8192 |> ignore done;
  Rng.generate 17 |> Cstruct.hexdump

let hash = `MD5

let m1 = Hash.module_of hash
let t5 _ =
  Format.printf "-> %b %b\n%!"
    Hash.(module_of hash == m1)
    Hash.(module_of hash == module_of hash)

let t6 _ =
  let measure = `Cputime_ns
  and crap    = Rng.generate 20 in
  Unmark.time ~tag:"get" ~n:1000 ~measure
    (fun () -> Hash.module_of `SHA1 |> ignore);
  Unmark.time ~tag:"desu" ~n:1000 ~measure
    (fun () -> Hash.MD5.digest crap |> ignore);
  Unmark.time ~tag:"desu" ~n:1000 ~measure
    (fun () -> Hash.digest `MD5 crap |> ignore);
  ()

let rec rc ?(blk=(1024*64)) ~key h n =
  let open Cipher_stream.ARC4 in
  if n > 0 then
    let n1 = min n blk in
    let r = encrypt ~key (Cstruct.create n1) in
    rc ~blk ~key:r.key (Hash.SHAd256.feed h r.message) (n - n1)
  else h

let t7 n =
  let key = Cipher_stream.ARC4.of_secret (Cstruct.of_string "\000") in
  Format.printf "--> %a\n%!" Uncommon.Cs.hexdump
    Hash.SHAd256.(rc ~key empty n |> get)

let () = t7 ((2 lsl 12) - 100)
  (* (2 lsl 28) *)
