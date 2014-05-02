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
  (fun ~(key : pub ) msg ->
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
  let size = pub_bits key / 8 in (* .... *)
  Numeric.Z.(to_cstruct_be ~size @@ encrypt_z ~key @@ of_cstruct_be cs)

and decrypt ?(mask = `Yes) ~key cs =
  let size = priv_bits key / 8 in (* .... *)
  Numeric.Z.(to_cstruct_be ~size @@ decrypt_z ~mask ~key @@ of_cstruct_be cs)


(* XXX
 * All kinds bad. Default public exponent should probably be smaller than
 * 2^16+1. Two bits of key are rigged.
 *)
let generate ?g ?(e = Z.of_int 0x10001) bits =

  Printf.printf "DON'T use this to generate actual keys.\n%!";

  let (p, q) =
    let rec attempt bits =
      let (p, q) = (Rng.prime ?g ~bits, Rng.prime ?g ~bits) in
      let cond = (p <> q) &&
                 Z.(gcd e (pred p) = one) &&
                 Z.(gcd e (pred q) = one) in
      if cond then (p, q) else attempt bits in
    attempt (bits / 2) in
  priv_of_primes ~e ~p ~q


let print_key { e; d; n; p; q; dp; dq; q' } =
  let f = Z.to_string in
  Printf.printf
"RSA key
  e : %s
  d : %s
  n : %s
  p : %s
  q : %s
  dp: %s
  dq: %s
  q': %s\n%!" (f e) (f d) (f n) (f p) (f q) (f dp) (f dq) (f q')
