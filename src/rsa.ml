open Sexplib.Conv
open Uncommon

exception Invalid_message

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
    if msg < Z.one || n <= msg then raise Invalid_message in
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

  let min_pad = 8 + 3

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
        | (i, 0x00) when i >= min_pad && ok
                    -> ignore (go false (succ i)); Some (succ i)
        | (i, b   ) -> go (is_pad b && ok) (succ i) in
    go true 0 |> Option.map ~f:(fun off -> sub cs off (n - off))

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
    if size - len msg < min_pad then raise Invalid_message ;
    transform (pad size msg)

  let unpadded unpad transform keybits msg =
    if len msg = cdiv keybits 8 then
      try unpad (transform msg) with Invalid_message -> None
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

module MGF1 (H : Hash.T) = struct

  open Cstruct
  open Numeric

  let repr = Numeric.Int32.to_cstruct_be ~size:4

  (* Assumes len < 2^32 * H.digest_size. *)
  let mask ~seed ~len =
    Range.of_int32 0l (Int32.of_int @@ cdiv len H.digest_size - 1)
    |> List.map (fun c -> H.digestv [seed; repr c])
    |> Cs.concat
    |> fun cs -> sub cs 0 len

end

module OAEP (H : Hash.T) = struct

  open Cstruct

  module MGF = MGF1(H)

  let mgf seed len = MGF.mask ~seed ~len

  let hlen  = H.digest_size
  and hlen1 = H.digest_size + 1

  let (bx00, bx01) = Cstruct.(of_string "\000", of_string "\001")

  let eme_oaep_encode ?g ?(label = Cs.empty) ~k msg =
    let seed  = Rng.generate ?g hlen
    and pad   = Cs.create_with (k - len msg - 2 * hlen1) 0x00 in
    let db    = Cs.concat [ H.digest label ; pad ; bx01 ; msg ] in
    let mdb   = Cs.(db lxor mgf seed (k - hlen1)) in
    let mseed = Cs.(seed lxor mgf mdb hlen) in
    Cs.concat [ bx00 ; mseed ; mdb ]

  let eme_oaep_decode ?(label = Cs.empty) ~k msg =
    let y      = get_uint8 msg 0
    and ms     = sub msg 1 hlen
    and mdb    = sub msg hlen1 (len msg - hlen1) in
    let db     = Cs.(mdb lxor mgf (ms lxor mgf mdb hlen) (k - hlen1)) in
    let hmatch = Cs.equal ~mask:true (sub db 0 hlen) H.(digest label) in
    match Cs.find_uint8 ~off:hlen ~f:((<>) 0x00) db with
    | None   -> None
    | Some i ->
        let b = get_uint8 db i
        and m = sub db (i + 1) (len db - i - 1) in
        if y = 0x00 && b = 0x01 && hmatch then Some m else None

  (* XXX check ~label len does not exceed hash input limitation? *)

  let encrypt ?g ?label ~key msg =
    let k = cdiv (pub_bits key) 8 in
    if len msg > k - 2 * hlen1 then raise Invalid_message ;
    encrypt ~key @@ eme_oaep_encode ?g ?label ~k msg

  let decrypt ?mask ?label ~key msg =
    let k = cdiv (priv_bits key) 8 in
    if len msg <> k || k < 2 * hlen1 then
      None
    else try
      eme_oaep_decode ?label ~k @@ decrypt ?mask ~key msg
    with Invalid_message -> None

end
