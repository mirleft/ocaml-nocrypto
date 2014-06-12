open Common

type pub  = { e : Z.t ; n : Z.t }

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
}

type mask = [ `No | `Yes | `Yes_with of Rng.g ]

let pub ~e ~n =
  Numeric.Z.({
    e = of_cstruct_be e ;
    n = of_cstruct_be n ;
  })

let priv ~e ~d ~n ~p ~q ~dp ~dq ~q' =
  Numeric.Z.({
    e  = of_cstruct_be e  ;
    d  = of_cstruct_be d  ;
    n  = of_cstruct_be n  ;
    p  = of_cstruct_be p  ;
    q  = of_cstruct_be q  ;
    dp = of_cstruct_be dp ;
    dq = of_cstruct_be dq ;
    q' = of_cstruct_be q' ;
  })

let priv_of_primes ~e ~p ~q =
  let n  = Z.(p * q)
  and d  = Z.(invert e (pred p * pred q)) in
  let dp = Z.(d mod (pred p))
  and dq = Z.(d mod (pred q))
  and q' = Z.(invert q p) in
  { e  = e  ; d  = d  ; n = n ;
    p  = p  ; q  = q  ;
    dp = dp ; dq = dq ; q' = q' }

let priv' ~e ~p ~q =
  let (e, p, q) =
    Numeric.Z.(of_cstruct_be e, of_cstruct_be p, of_cstruct_be q) in
  priv_of_primes ~e ~p ~q

let pub_of_priv ({ e; n } : priv) = { e = e ; n = n }

(* XXX handle this more gracefully... *)
let pub_bits ({ n } : pub)   = Numeric.Z.bits n
and priv_bits ({ n } : priv) = Numeric.Z.bits n

let encrypt_unsafe ~key: ({ e; n } : pub) msg = Z.(powm msg e n)

let mod_ x n = match Z.sign x with
  | -1 -> Z.(x mod n + n)
  |  _ -> Z.(x mod n)

let decrypt_unsafe ~key: ({ p; q; dp; dq; q' } : priv) c =
  let m1 = Z.(powm c dp p)
  and m2 = Z.(powm c dq q) in
  let h  = Z.(mod_ (q' * (m1 - m2)) p) in
  Z.(m2 + h * q)

(* Timing attacks, you say? *)
let decrypt_blinded_unsafe ?g ~key: ({ e; n } as key : priv) c =

  let rec nonce () =
    let x = Rng.Z.gen_r ?g z_two n in
    if Z.(gcd x n = one) then x else nonce () in

  let r  = nonce () in
  let r' = Z.(invert r n) in
  let x  = decrypt_unsafe ~key Z.(powm r e n * c mod n) in
  Z.(r' * x mod n)


let (encrypt_z, decrypt_z) =
  let check_params n msg =
    if msg >= n then invalid_arg "RSA: key too small" ;
    if msg < Z.one then invalid_arg "RSA: non-positive message"
  in
  (fun ~(key : pub) msg ->
    check_params key.n msg ;
    encrypt_unsafe ~key msg),
  (fun ?(mask = `Yes) ~(key : priv) msg ->
    check_params key.n msg ;
    match mask with
    | `No         -> decrypt_unsafe            ~key msg
    | `Yes        -> decrypt_blinded_unsafe    ~key msg
    | `Yes_with g -> decrypt_blinded_unsafe ~g ~key msg )

(* XXX (outer) padding *)
let encrypt ~key cs =
  let size = cdiv (pub_bits key) 8 in (* .... *)
  Numeric.Z.(to_cstruct_be ~size @@ encrypt_z ~key @@ of_cstruct_be cs)

and decrypt ?(mask = `Yes) ~key cs =
  let size = cdiv (priv_bits key) 8 in (* .... *)
  Numeric.Z.(to_cstruct_be ~size @@ decrypt_z ~mask ~key @@ of_cstruct_be cs)


(* XXX
 * All kinds bad. Default public exponent should probably be smaller than
 * 2^16+1. Two bits of key are rigged.
 * And even then the key is not guaranteed to be bull `bits` long.
 *)
let generate ?g ?(e = Z.of_int 0x10001) promise bits =

  let `Yes_this_is_debug_session = promise in

  let (p, q) =
    let rec attempt bits =
      let (p, q) = (Rng.prime ?g ~bits, Rng.prime ?g ~bits) in
      let cond = (p <> q) &&
                 Z.(gcd e (pred p) = one) &&
                 Z.(gcd e (pred q) = one) in
      if cond then (p, q) else attempt bits in
    attempt (bits / 2) in
  priv_of_primes ~e ~p ~q


let string_of_private_key { e; d; n; p; q; dp; dq; q' } =
  let f = Z.to_string in
  Printf.sprintf
"RSA key
  e : %s
  d : %s
  n : %s
  p : %s
  q : %s
  dp: %s
  dq: %s
  q': %s" (f e) (f d) (f n) (f p) (f q) (f dp) (f dq) (f q')


module PKCS1 = struct

  open Cstruct

  (* inspiration from RFC3447 EMSA-PKCS1-v1_5 and rsa_sign.c from OpenSSL *)
  (* also ocaml-ssh kex.ml *)
  (* msg.length must be 36 (16 MD5 + 20 SHA1) in TLS-1.0/1.1! *)
  let pad_01 size msg =
    let n = len msg in
    match size - n with
    | pad when pad <= 3 -> None
    | pad ->
        let cs = create size in
        BE.set_uint16 cs 0 0x0001 ;
        Cs.fill ~off:2 ~len:(pad - 3) cs 0xff ;
        set_uint8 cs (pad - 1) 0x00 ;
        blit msg 0 cs pad n ;
        Some cs

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

  let sign ~key msg =
    (* XXX XXX temp *)
    let size = priv_bits key / 8 in
    map_opt ~f:(decrypt ~key) @@ pad_01 size msg

  let verify ~key data =
    unpad_01 (encrypt ~key data)

  (* we're supposed to do the following:
      0x00 0x02 <random_not_zero> 0x00 data *)
  let pad_02 ?g size msg =
    let n = len msg in
    match size - n with
    | pad when pad <= 3 -> None
    | pad ->
        let cs      = create size in
        let block   = Rng.(block_size * cdiv pad block_size) in
        let pop buf = (get_uint8 buf 0, shift buf 1) in
        let rec copybyte nonce = function
          | i when i = pad - 1 -> ()
          | i ->
              match
                try pop nonce with Invalid_argument _ ->
                  pop (Rng.generate ?g block)
              with
              | (0x00, nonce') -> copybyte nonce' i
              | (x   , nonce') -> set_uint8 cs i x ; copybyte nonce' (succ i)
        in
        BE.set_uint16 cs 0 0x0002 ;
        copybyte Cs.empty 2 ;
        set_uint8 cs (pad - 1) 0x00 ;
        blit msg 0 cs pad n ;
        Some cs

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

  let encrypt ~key msg =
    (* XXX XXX this is temp. *)
    let msglen = pub_bits key / 8 in
    match pad_02 msglen msg with
    | None      -> invalid_arg "RSA.PKCS1.encrypt: key too small"
    | Some msg' -> encrypt ~key msg'

  let decrypt ?mask ~key msg =
    (* XXX XXX temp *)
    let msglen = priv_bits key / 8 in
    if Cstruct.len msg = msglen then
      unpad_02 (decrypt ?mask ~key msg)
    else None

end
