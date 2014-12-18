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

  open Cstruct

  (* inspiration from RFC3447 EMSA-PKCS1-v1_5 and rsa_sign.c from OpenSSL *)
  (* also ocaml-ssh kex.ml *)
  let pad_01 size msg =
    let n   = len msg in
    let pad = size - n
    and cs  = create size in
    BE.set_uint16 cs 0 0x0001 ;
    Cs.fill (sub cs 2 (pad - 3)) 0xff ;
    set_uint8 cs (pad - 1) 0x00 ;
    blit msg 0 cs pad n ;
    cs

  (* No time-masking: public-key operation. *)
  let unpad_01 msg =
    try
      match BE.get_uint16 msg 0 with
      | 0x0001 ->
          let rec ff i =
            match get_uint8 msg i with
            | 0xff -> ff (succ i)
            | 0x00 -> Some (shift msg (i + 1))
            | _    -> None in
          ff 2
      | _ -> None
    with Invalid_argument _ -> None

  let min_pad = 4

  let sign ?mask ~key msg =
    let size = cdiv (priv_bits key) 8 in
    if size - len msg < min_pad then
      invalid_arg "RSA.PKCS1.sign: key too small"
    else decrypt ?mask ~key (pad_01 size msg)

  let verify ~key data =
    try
      unpad_01 (encrypt ~key data)
    with Invalid_argument _ -> None
    (* XXX switch to custom exn *)

  (* 0x00 0x02 <random_not_zero> 0x00 data *)
  let pad_02 ?g size msg =
    let n   = len msg in
    let pad = size - n
    and cs  = create size in
    let block   = Rng.(block_size * cdiv pad block_size) in
    let rec copybyte nonce = function
      | i when i = pad - 1   -> ()
      | i when Cs.null nonce -> copybyte Rng.(generate ?g block) i
      | i ->
          match (get_uint8 nonce 0, shift nonce 1) with
          | (0x00, nonce') -> copybyte nonce' i
          | (x   , nonce') -> set_uint8 cs i x ; copybyte nonce' (succ i)
    in
    BE.set_uint16 cs 0 0x0002 ;
    copybyte Cs.empty 2 ;
    set_uint8 cs (pad - 1) 0x00 ;
    blit msg 0 cs pad n ;
    cs

  let unpad_02 msg =
    let n = len msg in
    let rec scan ok padding = function
      | i when i = n -> (ok, padding)
      | i ->
          match (i, get_uint8 msg i, padding) with
          | (0, b, _   ) -> scan (ok && b = 0) padding (succ i)
          | (1, b, _   ) -> scan (ok && b = 2) padding (succ i)
          | (_, 0, None) -> scan ok (Some (succ i)) (succ i)
          | _            -> scan ok padding (succ i) 
    in
    if n > 3 then
      match scan true None 0 with
      | (true, Some start) -> Some (shift msg start)
      | _                  -> None
    else None

  let encrypt ?g ~key msg =
    let size = cdiv (pub_bits key) 8 in
    if size - len msg < min_pad then
      invalid_arg "RSA.PKCS1.encrypt: key too small"
    else encrypt ~key (pad_02 ?g size msg)

  let decrypt ?mask ~key msg =
    let msglen = cdiv (priv_bits key) 8 in
    if Cstruct.len msg = msglen then
      unpad_02 (decrypt ?mask ~key msg)
    else None

end
