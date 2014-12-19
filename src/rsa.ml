open Sexplib.Conv
open Uncommon

exception Invalid_message_size

type pub  = { e : Z.t ; n : Z.t } with sexp

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
} with sexp

type mask = [ `No | `Yes | `Yes_with of Rng.g ]

let priv_of_primes ~e ~p ~q =
  let n  = Z.(p * q)
  and d  = Z.(invert e (pred p * pred q)) in
  let dp = Z.(d mod (pred p))
  and dq = Z.(d mod (pred q))
  and q' = Z.(invert q p) in
  { e; d; n; p; q; dp; dq; q' }

let pub_of_priv ({ e; n; _ } : priv) = { e ; n }

(* XXX handle this more gracefully... *)
let pub_bits  ({ n; _ } : pub)  = Numeric.Z.bits n
and priv_bits ({ n; _ } : priv) = Numeric.Z.bits n

let encrypt_unsafe ~key: ({ e; n } : pub) msg = Z.(powm msg e n)

let decrypt_unsafe ~key: ({ p; q; dp; dq; q'; _} : priv) c =
  let m1 = Z.(powm c dp p)
  and m2 = Z.(powm c dq q) in
  let h  = Z.(erem (q' * (m1 - m2)) p) in
  Z.(h * q + m2)

let decrypt_blinded_unsafe ?g ~key: ({ e; n; _} as key : priv) c =

  let rec nonce () =
    let x = Rng.Z.gen_r ?g Z.two n in
    if Z.(gcd x n = one) then x else nonce () in

  let r  = nonce () in
  let r' = Z.(invert r n) in
  let x  = decrypt_unsafe ~key Z.(powm r e n * c mod n) in
  Z.(r' * x mod n)


let (encrypt_z, decrypt_z) =
  let check_params n msg =
    if msg < Z.one || n <= msg then raise Invalid_message_size in
  (fun ~(key : pub) msg ->
    check_params key.n msg ;
    encrypt_unsafe ~key msg),
  (fun ?(mask = `Yes) ~(key : priv) msg ->
    check_params key.n msg ;
    match mask with
    | `No         -> decrypt_unsafe            ~key msg
    | `Yes        -> decrypt_blinded_unsafe    ~key msg
    | `Yes_with g -> decrypt_blinded_unsafe ~g ~key msg )

let reformat out f =
  Numeric.Z.(to_cstruct_be ~size:(cdiv out 8) &. f &. of_cstruct_be ?bits:None)

let encrypt ~key              = reformat (pub_bits key)  (encrypt_z ~key)
and decrypt ?(mask=`Yes) ~key = reformat (priv_bits key) (decrypt_z ~mask ~key)


let generate ?g ?(e = Z.(~$0x10001)) bits =

  if bits < 10 then
    invalid_arg "Rsa.generate: requested key size < 10 bits";
  if Numeric.(Z.bits e >= bits || not (pseudoprime e)) || e < Z.three then
    invalid_arg "Rsa.generate: e invalid or too small" ;

  let msb = 2
  and (pb, qb) = (bits / 2, bits - bits / 2) in
  let (p, q) =
    let rec attempt () =
      let (p, q) = Rng.(prime ?g ~msb ~bits:pb, prime ?g ~msb ~bits:qb) in
      let cond = (p <> q) &&
                 Z.(gcd e (pred p) = one) &&
                 Z.(gcd e (pred q) = one) in
      if cond then (max p q, min p q) else attempt () in
    attempt () in
  priv_of_primes ~e ~p ~q


module PKCS1 = struct

  let min_pad = 3

  open Cstruct

  let pad ~mark ~padding size msg =
    let n   = len msg in
    let pad = size - n
    and cs  = create size in
    BE.set_uint16 cs 0 mark ;
    padding (sub cs 2 (pad - 3)) ;
    set_uint8 cs (pad - 1) 0x00 ;
    blit msg 0 cs pad n ;
    cs

  let unpad ~mark ~is_pad cs =
    let n = len cs in
    let rec go ok i =
      if i = n then None else
        match (i, get_uint8 cs i) with
        | (0, b   ) -> go (b = 0x00 && ok) (succ i)
        | (1, b   ) -> go (b = mark && ok) (succ i)
        | (i, 0x00) when i >= min_pad -> Some (ok, i + 1)
        | (i, b   ) -> go (is_pad b && ok) (succ i) in
    match go true 0 with
    | Some (true, off) -> Some (sub cs off (n - off))
    | _                -> None

  let pad_01 =
    pad ~mark:0x01 ~padding:(fun cs -> Cs.fill cs 0xff)

  let pad_02 ?g =
    pad ~mark:0x02 ~padding:(fun cs ->
      let n     = len cs in
      let block = Rng.(block_size * cdiv n block_size) in
      let rec go nonce i j =
        if i = n then () else
        if j = block then go Rng.(generate ?g block) i 0 else
          match get_uint8 nonce j with
          | 0x00 -> go nonce i (succ j)
          | x    -> set_uint8 cs i x ; go nonce (succ i) (succ j) in
      go Rng.(generate ?g block) 0 0
    )

  let unpad_01 = unpad ~mark:0x01 ~is_pad:(fun b -> b = 0xff)

  let unpad_02 = unpad ~mark:0x02 ~is_pad:(fun b -> b <> 0x00)

  let padded pad transform keybits msg =
    let size = cdiv keybits 8 in
    if size - len msg < min_pad then raise Invalid_message_size ;
    transform (pad size msg)

  let unpadded unpad transform keybits msg =
    if len msg = cdiv keybits 8 then
      try unpad (transform msg) with Invalid_message_size -> None
    else None

  let sign ?mask ~key msg =
    padded pad_01 (decrypt ?mask ~key) (priv_bits key) msg

  let verify ~key msg =
    unpadded unpad_01 (encrypt ~key) (pub_bits key) msg

  let encrypt ?g ~key msg =
    padded (pad_02 ?g) (encrypt ~key) (pub_bits key) msg

  let decrypt ?mask ~key msg =
    unpadded unpad_02 (decrypt ?mask ~key) (priv_bits key) msg

end
