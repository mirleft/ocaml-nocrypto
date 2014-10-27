open Sexplib.Conv
open Uncommon

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

type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `Exactly of int * int ]

let expand_size = function
  | `Fips1024  -> (1024, 160)
  | `Fips2048  -> (2048, 256)
  | `Fips3072  -> (3072, 256)
  | `Exactly (l, n) -> (l, n)

type mask = [ `No | `Yes | `Yes_with of Rng.g ]

let expand_mask = function
  | `No         -> `No
  | `Yes        -> `Yes None
  | `Yes_with g -> `Yes (Some g)

(*
 * FIPS.186-4-style derivation:
 * - p and q are derived using a method numerically like the one described in
 *   A.1.1.2, adapted to use the native rng.
 * - g is derived as per A.2.1.
 *)
let params ?g size =
  let (l, n) = expand_size size in
  let q = Rng.prime ?g ~msb:1 ~bits:n in
  let p =
    let q_q  = Z.(q * ~$2)
    and mask = Z.((lsl) one) (l - 1) in
    until Numeric.pseudoprime @@ fun () ->
      let w = Rng.Z.gen_bits ?g l in
      let x = Z.(w lor mask) in
      Z.(x - (x mod q_q) + one) in
  let gg =
    let e = Z.(pred p / q) in
    until ((<>) Z.one) @@ fun () ->
      let h = Rng.Z.gen_r ?g Z.(~$2) Z.(pred p) in
      Z.(powm h e p) in
  (p, q, gg)

let generate ?g size =
  let (p, q, gg) = params ?g size in
  let x = Rng.Z.gen_r ?g Z.one q in
  let y = Z.(powm gg x p) in
  { p; q; gg; x; y }

let z_of_digest ~fips bits =
  Numeric.Z.of_cstruct_be ?bits:(if fips then Some bits else None)

module K_gen (H : Hash.T) = struct

  module R_gen = Hmac_drgb.Make (H)
  module R_num = Rng.Numeric_of (R_gen)

  let () = R_num.strict true

  let z_gen ~key:{ q; x; _ } z =
    let repr = Numeric.Z.(to_cstruct_be ~size:(cdiv (bits q) 8)) in
    let g    = R_gen.create () in
    R_gen.reseed ~g Cs.(repr x <> repr Z.(z mod q));
    R_num.Z.gen_r ~g Z.one q

  let generate ~key cs =
    z_gen ~key (z_of_digest ~fips:true Numeric.Z.(bits key.q) cs)
end

module K_gen_sha256 = K_gen (Hash.SHA256)

let rec sign_z ?(mask = `Yes) ?k:k0 ~key:({ p; q; gg; x; _ } as key) z =
  let k  = match k0 with Some k -> k | None -> K_gen_sha256.z_gen ~key z in
  let k' = Z.invert k q
  and r  = match expand_mask mask with
    | `No    -> Z.(powm gg k p mod q)
    | `Yes g ->
        let m  = Rng.Z.gen_r ?g Z.one q in
        let m' = Z.invert m q in
        Z.(powm (powm gg m p) (m' * k mod q) p mod q) in
  let s = Z.(k' * (z + x * r) mod q) in
  if r = Z.zero || s = Z.zero then sign_z ~mask ?k:k0 ~key z else (r, s)

let verify_z ~key:({ p; q; gg; y }: pub ) (r, s) z =
  let v () =
    let w  = Z.invert s q in
    let u1 = Z.(z * w mod q)
    and u2 = Z.(r * w mod q) in
    Z.((powm gg u1 p * powm y u2 p) mod p mod q) in
  Z.zero < r && r < q && Z.zero < s && s < q && v () = r

let sign ?mask ?k ?(fips = true) ~(key : priv) digest =
  let bits   = Numeric.Z.bits key.q in
  let size   = cdiv bits 8 in
  let (r, s) = sign_z ?mask ?k ~key (z_of_digest ~fips bits digest) in
  Numeric.Z.(to_cstruct_be ~size r, to_cstruct_be ~size s)

let verify ?(fips = true) ~(key : pub) (r, s) digest =
  let z      = z_of_digest ~fips Numeric.Z.(bits key.q) digest in
  let (r, s) = Numeric.Z.(of_cstruct_be r, of_cstruct_be s) in
  verify_z ~key (r, s) z
