open Uncommon

exception Insufficient_key

type pub  = { e : Z.t ; n : Z.t }

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
}

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
    if msg < Z.one || n <= msg then raise Insufficient_key in
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


let rec generate ?g ?(e = Z.(~$0x10001)) bits =
  if bits < 10 then
    Raise.invalid "Rsa.generate: requested key size (%d) < 10 bits" bits;
  if Numeric.(Z.bits e >= bits || not (pseudoprime e)) || e < Z.three then
    Raise.invalid "Rsa.generate: e invalid or too small";

  let (pb, qb) = (bits / 2, bits - bits / 2) in
  let (p, q)   = Rng.(prime ?g ~msb:2 pb, prime ?g ~msb:2 qb) in
  let cond     = (p <> q) &&
                 Z.(gcd e (pred p) = one) &&
                 Z.(gcd e (pred q) = one) in
  if cond then
    priv_of_primes ~e ~p:(max p q) ~q:(min p q)
  else generate ?g ~e bits



let b   = Cs.b
let cat = Cstruct.concat

let (bx00, bx01) = (b 0x00, b 0x01)


module PKCS1 = struct

  let min_pad = 8 + 3

  open Cstruct


  (* XXX Generalize this into `Rng.samplev` or something. *)
  let generate_with ?g ~f n =
    let cs = create n
    and k  = let b = Rng.block g in Rng.(b * cdiv n b) in
    let rec go nonce i j =
      if i = n then cs else
      if j = k then go Rng.(generate ?g k) i 0 else
      match get_uint8 nonce j with
      | b when f b -> set_uint8 cs i b ; go nonce (succ i) (succ j)
      | _          -> go nonce i (succ j) in
    go Rng.(generate ?g k) 0 0


  let pad ~mark ~padding k msg =
    let pad = padding (k - len msg - 3) in
    cat [ bx00 ; b mark ; pad ; bx00 ; msg ]

  let unpad ~mark ~is_pad cs =
    let f = not &. is_pad in
    let i = Cs.ct_find_uint8 ~off:2 ~f cs |> Option.get ~def:2
    in
    let c1 = get_uint8 cs 0 = 0x00
    and c2 = get_uint8 cs 1 = mark
    and c3 = get_uint8 cs i = 0x00
    and c4 = i + 1 >= min_pad in
    if c1 && c2 && c3 && c4 then
      Some (sub cs (i + 1) (len cs - i - 1))
    else None

  let pad_01    = pad ~mark:0x01 ~padding:(Cs.create ~init:0xff)
  let pad_02 ?g = pad ~mark:0x02 ~padding:(generate_with ?g ~f:((<>) 0x00))

  let unpad_01 = unpad ~mark:0x01 ~is_pad:((=) 0xff)
  let unpad_02 = unpad ~mark:0x02 ~is_pad:((<>) 0x00)

  let padded pad transform keybits msg =
    let size = bytes keybits in
    if size - len msg < min_pad then raise Insufficient_key ;
    transform (pad size msg)

  let unpadded unpad transform keybits msg =
    if len msg = bytes keybits then
      try unpad (transform msg) with Insufficient_key -> None
    else None

  let sig_encode ?mask ~key msg =
    padded pad_01 (decrypt ?mask ~key) (priv_bits key) msg

  let sig_decode ~key msg =
    unpadded unpad_01 (encrypt ~key) (pub_bits key) msg

  let encrypt ?g ~key msg =
    padded (pad_02 ?g) (encrypt ~key) (pub_bits key) msg

  let decrypt ?mask ~key msg =
    unpadded unpad_02 (decrypt ?mask ~key) (priv_bits key) msg

end

module MGF1 (H : Hash.S) = struct

  open Cstruct

  let repr = Numeric.Int32.to_cstruct_be ~size:4

  (* Assumes len < 2^32 * H.digest_size. *)
  let mgf ~seed len =
    let rec go acc c = function
      | 0 -> sub (cat (List.rev acc)) 0 len
      | n -> go (H.digestv [ seed ; repr c ] :: acc) Int32.(succ c) (pred n) in
    go [] 0l (cdiv len H.digest_size)

  let mask ~seed cs = Cs.xor (mgf ~seed (len cs)) cs

end

module OAEP (H : Hash.S) = struct

  open Cstruct

  module MGF = MGF1(H)

  let hlen = H.digest_size

  let max_msg_bytes k = k - 2 * hlen - 2

  let eme_oaep_encode ?g ?(label = Cs.empty) k msg =
    let seed  = Rng.generate ?g hlen
    and pad   = Cs.create (max_msg_bytes k - len msg) in
    let db    = cat [ H.digest label ; pad ; bx01 ; msg ] in
    let mdb   = MGF.mask ~seed db in
    let mseed = MGF.mask ~seed:mdb seed in
    cat [ bx00 ; mseed ; mdb ]

  let eme_oaep_decode ?(label = Cs.empty) msg =
    let (b0, ms, mdb) = Cs.split3 msg 1 hlen in
    let db = MGF.mask ~seed:(MGF.mask ~seed:mdb ms) mdb in
    let i  = Cs.ct_find_uint8 ~off:hlen ~f:((<>) 0x00) db |> Option.get ~def:0
    in
    let c1 = Cs.ct_eq (sub db 0 hlen) H.(digest label)
    and c2 = get_uint8 b0 0 = 0x00
    and c3 = get_uint8 db i = 0x01 in
    if c1 && c2 && c3 then
      Some (shift db (i + 1))
    else None

  let encrypt ?g ?label ~key msg =
    let k = bytes (pub_bits key) in
    if len msg > max_msg_bytes k then raise Insufficient_key
    else encrypt ~key @@ eme_oaep_encode ?g ?label k msg

  let decrypt ?mask ?label ~key em =
    let k = bytes (priv_bits key) in
    if len em <> k || max_msg_bytes k < 0 then None
    else try
      eme_oaep_decode ?label @@ decrypt ?mask ~key em
    with Insufficient_key -> None

  (* XXX Review rfc3447 7.1.2 and
   * http://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf
   * again for timing properties. *)

  (* XXX expose seed for deterministic testing? *)

end

module PSS (H: Hash.S) = struct

  open Cstruct

  module MGF = MGF1(H)

  let hlen = H.digest_size

  let bxbc = b 0xbc

  let b0mask embits = 0xff lsr ((8 - embits mod 8) mod 8)

  let emsa_pss_encode ?g slen emlen msg =
    let n    = bytes emlen
    and salt = Rng.generate ?g slen in
    let h    = H.digestv [ Cs.create 8 ; H.digest msg ; salt ] in
    let db   = cat [ Cs.create (n - slen - hlen - 2) ; bx01 ; salt ] in
    let mdb  = MGF.mask ~seed:h db in
    set_uint8 mdb 0 @@ get_uint8 mdb 0 land b0mask emlen ;
    cat [ mdb ; h ; bxbc ]

  let emsa_pss_verify slen emlen em msg =
    let (mdb, h, bxx) = Cs.split3 em (em.len - hlen - 1) hlen in
    let db   = MGF.mask ~seed:h mdb in
    set_uint8 db 0 (get_uint8 db 0 land b0mask emlen) ;
    let salt = shift db (len db - slen) in
    let h'   = H.digestv [ Cs.create 8 ; H.digest msg ; salt ]
    and i    = Cs.ct_find_uint8 ~f:((<>) 0x00) db |> Option.get ~def:0
    in
    let c1 = lnot (b0mask emlen) land get_uint8 mdb 0 = 0x00
    and c2 = i = em.len - hlen - slen - 2
    and c3 = get_uint8 db  i = 0x01
    and c4 = get_uint8 bxx 0 = 0xbc
    and c5 = Cs.ct_eq h h' in
    c1 && c2 && c3 && c4 && c5

  let min_key_bits slen = 8 * (hlen + slen + 1) + 2

  (* XXX RSA masking? *)
  let sign ?g ?(slen = hlen) ~key msg =
    let b = priv_bits key in
    if b < min_key_bits slen then raise Insufficient_key
    else decrypt ~mask:`No ~key @@ emsa_pss_encode ?g slen (b - 1) msg

  let verify ?(slen = hlen) ~key ~signature msg =
    let b = pub_bits key
    and s = len signature in
    s = bytes b && b >= min_key_bits slen &&
    try
      let em = encrypt ~key signature in
      emsa_pss_verify slen (b - 1) (shift em (s - bytes (b - 1))) msg
    with Insufficient_key -> false

end
