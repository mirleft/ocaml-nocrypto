open Common

type pub  = { e : Z.t ; n : Z.t }

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
}

let pub ~e ~n = { e ; n }

let priv ~e ~d ~n ~p ~q ~dp ~dq ~q' = { e; d; n; p; q; dp; dq; q' }

let priv' ~e ~p ~q =
  let n  = Z.(p * q)
  and d  = Z.(invert e (pred p * pred q)) in
  let dp = Z.(d mod (pred p))
  and dq = Z.(d mod (pred q))
  and q' = Z.(invert q p) in
  priv ~e ~d ~n ~p ~q ~dp ~dq ~q'

let pub_of_priv ({ e; n } : priv) = { e = e ; n = n }


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
  (fun    ~(key : pub ) msg ->
    check_params key.n msg ; encrypt_unsafe ~key msg),
  (fun ?g ~(key : priv) msg ->
    check_params key.n msg ; decrypt_blinded_unsafe ?g ~key msg)

(* XXX (outer) padding *)
let encrypt    ~key cs =
  Numeric.Z.(to_cstruct_be @@ encrypt_z ~key @@ of_cstruct_be cs)

and decrypt ?g ~key cs =
  Numeric.Z.(to_cstruct_be @@ decrypt_z ?g ~key @@ of_cstruct_be cs)


(* XXX
 * All kinds bad. Default public exponent should probably be smaller than
 * 2^16+1. Two bits of key are rigged.
 *)
let generate ?g ?(e = Z.of_int 0x10001) bits =

  Printf.printf "DON'T use this to generate actual keys.\n%!";

  let (p, q) =
    let rec attempt bits =
      let (p, q) = (Rng.prime ?g bits, Rng.prime ?g bits) in
      let cond = (p <> q) &&
                 Z.(gcd e (pred p) = one) &&
                 Z.(gcd e (pred q) = one) in
      if cond then (p, q) else attempt bits in
    attempt (bits / 2) in
  priv' ~e ~p ~q


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



(* debug crap *)

let def_e   = Z.of_int 0x10001

let attempt bits =
  let m = Rng.generate (bits / 8 - 1) in
  Cstruct.hexdump m ;
  let e = if Z.(pow z_two bits < def_e) then Z.of_int 3 else def_e in
  let key =
    Printf.printf "+ generating...\n%!";
    generate ~e bits in
  print_key key ;
  let c =
    Printf.printf "+ encrypt...\n%!";
    encrypt ~key:(pub_of_priv key) m in
  Cstruct.hexdump c ;
  let d =
    Printf.printf "+ decrypt...\n%!";
    decrypt ~key c in
  Cstruct.hexdump d ;
  assert (CS.cs_equal m d) ;
  Printf.printf "* \n%!"

