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

let pub_equal (p : pub) (p' : pub) =
  Z.(p.e = p'.e) && Z.(p.n = p'.n)

(*
module PKCS1 = struct
  let padPKCS1_and_signRSA key msg =

    (* XXX XXX temp *)
    let len = RSA.priv_bits key / 8 in

    (* inspiration from RFC3447 EMSA-PKCS1-v1_5 and rsa_sign.c from OpenSSL *)
    (* also ocaml-ssh kex.ml *)
    (* msg.length must be 36 (16 MD5 + 20 SHA1) in TLS-1.0/1.1! *)
    let mlen = Cstruct.len msg in
    let padlen = len - mlen in
    if padlen > 3 then
      let out = Cstruct.create len in
      Cstruct.set_uint8 out 0 0;
      Cstruct.set_uint8 out 1 1;
      for i = 2 to (padlen - 2) do
        Cstruct.set_uint8 out i 0xff;
      done;
      Cstruct.set_uint8 out (pred padlen) 0;
      Cstruct.blit msg 0 out padlen mlen;
      Some (RSA.decrypt ~key out)
    else
      None

  let verifyRSA_and_unpadPKCS1 pubkey data =
    let dat = RSA.encrypt ~key:pubkey data in
    if (Cstruct.get_uint8 dat 0 = 0) && (Cstruct.get_uint8 dat 1 = 1) then
      let rec ff idx =
        match Cstruct.get_uint8 dat idx with
        | 0    -> Some (succ idx)
        | 0xff -> ff (succ idx)
        | _    -> None
      in
      match ff 2 with
      | Some start -> Some (Cstruct.shift dat start)
      | None       -> None
    else
      None

  let padPKCS1_and_encryptRSA pubkey data =
    (* we're supposed to do the following:
       0x00 0x02 <random_not_zero> 0x00 data *)

    (* XXX XXX this is temp. *)
    let msglen = RSA.pub_bits pubkey / 8 in

    let open Cstruct in
    let padlen = msglen - (len data) in
    let msg = create msglen in

    (* the header 0x00 0x02 *)
    set_uint8 msg 0 0;
    set_uint8 msg 1 2;

    let produce_random () = Rng.generate (2 * padlen) in

    (* the non-zero random *)
    let rec copybyte random = function
      | x when x = pred padlen -> ()
      | n                      ->
         if len random = 0 then
           copybyte (produce_random ()) n
         else
           let rest = shift random 1 in
           match get_uint8 random 0 with
           | 0 -> copybyte rest n
           | r -> set_uint8 msg n r;
                  copybyte rest (succ n)
    in
    copybyte (produce_random ()) 2;

    (* footer 0x00 *)
    set_uint8 msg (pred padlen) 0;

    (* merging all together *)
    blit data 0 msg padlen (len data);
    RSA.encrypt ~key:pubkey msg

  let decryptRSA_unpadPKCS1 key msg =
    (* XXX XXX temp *)
    let msglen = RSA.priv_bits key / 8 in

    let open Cstruct in
    if msglen == len msg then
      let dec = RSA.decrypt ~key msg in
      let rec check_padding cur start = function
        | 0                  -> let res = get_uint8 dec 0 = 0 in
                                check_padding (res && cur) 1 1
        | 1                  -> let res = get_uint8 dec 1 = 2 in
                                check_padding (res && cur) 2 2
        | n when n >= msglen -> start
        | n                  -> let res = get_uint8 dec n = 0 in
                                let nxt = succ n in
                                match cur, res with
                                | true, true -> check_padding false nxt nxt
                                | x   , _    -> check_padding x start nxt
      in
      let start = check_padding true 0 0 in
      Some (Cstruct.shift dec start)
    else
      None

end
 *)
