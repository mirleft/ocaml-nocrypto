open Sexplib.Conv
open Uncommon

(* good values for l,n are: (1024, 160) (2048, 224) (2048, 256) (3072, 256) *)

type pub  = { p : Z.t ; q : Z.t ; gg : Z.t ; y : Z.t } with sexp
type priv = { p : Z.t ; q : Z.t ; gg : Z.t ; x : Z.t ; y : Z.t } with sexp

type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `LN of int * int ]

let pub ~p ~q ~gg ~y =
  Numeric.Z.({
    p  = of_cstruct_be p  ;
    q  = of_cstruct_be q  ;
    gg = of_cstruct_be gg ;
    y  = of_cstruct_be y  ;
  })

let priv ~p ~q ~gg ~x ~y =
  Numeric.Z.({
    p  = of_cstruct_be p  ;
    q  = of_cstruct_be q  ;
    gg = of_cstruct_be gg ;
    x  = of_cstruct_be x  ;
    y  = of_cstruct_be y  ;
  })

let pub_of_priv { p; q; gg; x; y } = { p; q; gg; y }

let expand_size = function
  | `Fips1024 -> (1024, 160)
  | `Fips2048 -> (2048, 256)
  | `Fips3072 -> (3072, 256)
  | `LN (l, n) -> (l, n)

let params ?g size =
  let (l, n) = expand_size size in

  let rec p_scan q a =
    let p = Z.(q * a + ~$1) in
    if Numeric.pseudoprime p then (p, a) else p_scan q Z.(a + ~$2) in

  let rec g_scan p a =
    let seed = Rng.Z.gen_r ?g Z.one p in
    let gg   = Z.(powm seed a p) in
    if gg <> Z.one then gg else g_scan p a in

  let q = Rng.prime ?g ~msb:1 ~bits:n in
  let (p, a) = p_scan q @@ Z.((lsl) ~$3) (l - n - 1) in
  let gg     = g_scan p a in
  (p, q, gg)

let generate ?g size =
  let (p, q, gg) = params ?g size in
  let x = Rng.Z.gen_r ?g Z.one q in
  let y = Z.(powm gg x p) in
  { p; q; gg; x; y }

(*
(* NIST FIPS 186-4 *)
let gen_k p q g =
  let c = Rng.Z.gen_r Z.one q in
  Z.(c mod (q - Z.one) + one)
 *)

(* RFC6979; Section 3.1 *)
let bits_to_int qlen input =
  let blen = 8 * Cstruct.len input in
  let i = Numeric.Z.of_cstruct_be input in
  if qlen < blen then
    (* take qlen leftmost things *)
    let shift = blen - qlen in
    Numeric.Z.(i lsr shift)
  else
    i

(* RFC6979; Section 3.2 *)
let generate_k hash h1 q x =
  let open Cstruct in
  let (<+>) = Cs.append in

  let hlen = Hash.digest_size hash
  and null = Cs.create_with 1 0
  and one = Cs.create_with 1 1
  and qlen = Numeric.Z.bits q
  in
  let h1 =
    let h1 = bits_to_int qlen h1 in
    let z2 = Z.(h1 - q) in
    let out = if z2 < Z.zero then h1 else z2 in
    Numeric.Z.to_cstruct_be ~size:(cdiv qlen 8) out
  in

  let x = Numeric.Z.to_cstruct_be ~size:(cdiv qlen 8) x in
  let v = Cs.create_with hlen 1 in
  let key = Cs.create_with hlen 0 in
  let key = Hash.mac hash ~key (v <+> null <+> x <+> h1) in
  let v = Hash.mac hash ~key v in
  let key = Hash.mac hash ~key (v <+> one <+> x <+> h1) in
  let v = Hash.mac hash ~key v in

  let rec doit key v =
    let rec grow t v =
      match cdiv qlen 8 - len t with
      | x when x = 0 -> (t, v)
      | x when x <= hlen ->
         let v = Hash.mac hash ~key v in
         (t <+> (Cstruct.sub v 0 x), v)
      | x ->
         let v = Hash.mac hash ~key v in
         grow (t <+> v) v
    in
    let t, v = grow (create 0) v in
    let k = bits_to_int qlen t in
    if Z.one <= k && k < q then
      k
    else
      let key = Hash.mac hash ~key (v <+> null) in
      let v = Hash.mac hash ~key v in
      doit key v
  in
  doit key v

type mask = [ | `No | `Yes ]

let sign_ { p; q; gg; x; _ } k inv_k m =
  let r = Z.((powm gg k p) mod q) in
  let s = Z.(inv_k * (m + x * r) mod q) in
  if r = Z.zero || s = Z.zero then
    None
  else
    Some (r, s)

let sign ~key:({ p; q; gg; x; _ } as priv) ?(mask = `Yes) ?k ~hash m =
  let size = cdiv (Numeric.Z.bits q) 8 in
  let hm = Hash.digest hash m in
  let hmnum = bits_to_int (Numeric.Z.bits q) hm in
  let rec tryme () =
    let k = match k with
      | Some k -> Numeric.Z.of_cstruct_be k
      | None -> generate_k hash hm q x
    in
    let key, k, inv_k, hmnum =
      match mask with
      | `No  -> (priv, k, Z.(invert k q), hmnum)
      | `Yes -> let blind = Rng.Z.gen_r Z.one q in
                ({ priv with x = Z.(x * blind) }, k, Z.(invert (blind * k) q), Z.(hmnum * blind))
    in
    match sign_ key k inv_k hmnum with
    | None -> tryme ()
    | Some (r, s) -> Numeric.Z.(to_cstruct_be ~size r, to_cstruct_be ~size s)
  in
  tryme ()

let verify ~key:({ p ; q ; gg ; y } : pub) ~hash m (r, s) =
  let r = Numeric.Z.of_cstruct_be r
  and s = Numeric.Z.of_cstruct_be s
  in
  let hm = Hash.digest hash m in
  let hm = bits_to_int (Numeric.Z.bits q) hm in
  if r > Z.zero && s > Z.zero && r < q && s < q then
    let w = Z.(invert s q) in
    let u1 = Z.(hm * w mod q) in
    let u2 = Z.(r * w mod q) in
    let v = Z.(((powm gg u1 p * powm y u2 p) mod p) mod q) in
    if v = r then
      true
    else
      false
  else
    false

