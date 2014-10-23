open Sexplib.Conv
open Uncommon

module Hmac_drgb_256 = Hmac_drgb.Make (Hash.SHA256)
module Hmac_num      = Rng.Numeric_of (Hmac_drgb_256)

type pub  = { p : Z.t ; q : Z.t ; gg : Z.t ; y : Z.t } with sexp
type priv = { p : Z.t ; q : Z.t ; gg : Z.t ; x : Z.t ; y : Z.t } with sexp

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

let pub_of_priv { p; q; gg; y; _ } = { p; q; gg; y }

type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `LN of int * int ]

let expand_size = function
  | `Fips1024  -> (1024, 160)
  | `Fips2048  -> (2048, 256)
  | `Fips3072  -> (3072, 256)
  | `LN (l, n) -> (l, n)

type mask = [ `No | `Yes | `Yes_with of Rng.g ]

let expand_mask = function
  | `No         -> `No
  | `Yes        -> `Yes None
  | `Yes_with g -> `Yes (Some g)

let params ?g size =
  let rec p_scan q a =
    let p = Z.(q * a + ~$1) in
    if Numeric.pseudoprime p then (p, a) else p_scan q Z.(a + ~$2)
  and g_scan p a =
    let seed = Rng.Z.gen_r ?g Z.one p in
    let gg   = Z.(powm seed a p) in
    if gg <> Z.one then gg else g_scan p a
  in
  let (l, n) = expand_size size in
  let q      = Rng.prime ?g ~msb:1 ~bits:n in
  let (p, a) = p_scan q @@ Z.((lsl) ~$3) (l - n - 1) in
  let gg     = g_scan p a in
  (p, q, gg)

let generate ?g size =
  let (p, q, gg) = params ?g size in
  let x = Rng.Z.gen_r ?g Z.one q in
  let y = Z.(powm gg x p) in
  { p; q; gg; x; y }

let k_hmac_drgb ~key:{ q; x; _ } z =
  let xh1 =
    let repr = Numeric.Z.(to_cstruct_be ~size:(cdiv (bits q) 8)) in
    Cs.(repr x <> repr Z.(z mod q)) in
  let g = Hmac_drgb_256.create () in
  Hmac_drgb_256.reseed ~g xh1;
  Hmac_num.Z.gen_r ~g Z.one q

let rec sign_z ?k:k0 ?(mask = `Yes) ~key:({ p; q; gg; x; _ } as key) z =
  let k  = match k0 with Some k -> k | None -> k_hmac_drgb ~key z in
  let k' = Z.invert k q
  and r  = match expand_mask mask with
    | `No    -> Z.(powm gg k p mod q)
    | `Yes g ->
        let m  = Rng.Z.gen_r ?g Z.one q in
        let m' = Z.invert m q in
        Z.(powm (powm gg m p) (m' * k mod q) p mod q) in
  let s  = Z.(k' * (z + x * r) mod q) in
  if r = Z.zero || s = Z.zero then
    sign_z ?k:k0 ~key z
  else (r, s)

let verify_z ~key:({ p; q; gg; y }: pub ) (r, s) z =
  let v () =
    let w  = Z.invert s q in
    let u1 = Z.(z * w mod q)
    and u2 = Z.(r * w mod q) in
    Z.((powm gg u1 p * powm y u2 p) mod p mod q) in
  Z.zero < r && r < q && Z.zero < s && s < q && v () = r

let sign ?mask ?k ~(key : priv) msg =
  let size = Numeric.Z.bits key.q
  and k    = Option.map Numeric.Z.of_cstruct_be k in
  let (r, s) = sign_z ?mask ?k ~key Numeric.Z.(of_bits_be msg size) in
  Numeric.Z.(to_cstruct_be ~size r, to_cstruct_be ~size s)

let verify ~(key : pub) (r, s) msg =
  let size = Numeric.Z.bits key.q in
  let (r, s, z) =
    Numeric.Z.(of_bits_be r size, of_bits_be s size, of_bits_be msg size) in
  verify_z ~key (r, s) z
