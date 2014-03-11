
let of_cstruct cs =
  let open Cstruct in
  let open Cstruct.BE in

  let rec loop acc = function
    | (_, 0) -> acc
      (* XXX larger words *)
    | (i, n) ->
        let x = Z.of_int @@ get_uint8 cs i in
        loop Z.((acc lsl 8) lor x) (succ i, pred n) in
  loop Z.zero (0, len cs)


let m1 = 0xffL
and m2 = 0xffffL
and m4 = 0xffffffffL
and m7 = 0xffffffffffffffL

let m1' = Z.of_int64 m1
let m2' = Z.of_int64 m2
let m4' = Z.of_int64 m4
let m7' = Z.of_int64 m7

let size_u z =
  let rec loop acc = function
    | z when z > m7' -> loop (acc + 7) Z.(shift_right z 56)
    | z when z > m4' -> loop (acc + 4) Z.(shift_right z 32)
    | z when z > m2' -> loop (acc + 2) Z.(shift_right z 16)
    | z when z > m1' -> loop (acc + 1) Z.(shift_right z 8 )
    | z              -> acc + 1 in
  loop 0 z

let to_cstruct z =
  let open Cstruct in
  let open Cstruct.BE in

  let byte = Z.of_int 0xff in
  let size = size_u z in
  let cs   = Cstruct.create size in

  let rec loop z = function
    | i when i < 0 -> ()
    | i ->
        set_uint8 cs i Z.(to_int @@ z land byte);
        loop Z.(shift_right z 8) (pred i) in

  ( loop z (size - 1) ; cs )


type pub  = { e : Z.t ; n : Z.t }

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
}

let pub  ~e ~n = { e ; n }

let pub_of_cstruct ~e ~n = { e = of_cstruct e; n = of_cstruct n }

let priv ~e ~d ~n ~p ~q ~dp ~dq ~q' = { e; d; n; p; q; dp; dq; q' }

let priv_of_cstruct ~e ~d ~n ~p ~q ~dp ~dq ~q' = {
  e  = of_cstruct e ; d  = of_cstruct d ; n = of_cstruct n;
  p  = of_cstruct p ; q  = of_cstruct q ;
  dp = of_cstruct dp; dq = of_cstruct dq; q' = of_cstruct q'
}

let pub_of_priv ({ e; n } : priv) = { e = e ; n = n }

let priv_of_primes ~e ~p ~q =
  let n  = Z.(p * q)
  and d  = Z.(invert e (pred p * pred q)) in
  let dp = Z.(d mod (pred p))
  and dq = Z.(d mod (pred q))
  and q' = Z.(invert q p) in
  priv ~e ~d ~n ~p ~q ~dp ~dq ~q'


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
let decrypt_blinded_unsafe ~key: ({ e; n } as key : priv) c =

  let two = Z.of_int 2 in
  let rec nonce () =
    let x = Rng.gen_z two n in
    if Z.(gcd x n = one) then x else nonce () in

  let r  = nonce () in
  Printf.printf "nonce: %d\n%!" Z.(to_int r);
  let r' = Z.(invert r n)
  and re = Z.(powm r e n) in

  let x = decrypt_unsafe ~key Z.((re * c) mod n) in

  Z.((r' * x) mod n)


let (encrypt_z, decrypt_z) =
  let aux op f ~key x =
    if x >= f key then
      invalid_arg "RSA key too small"
    else op ~key x in
  (aux encrypt_unsafe         (fun k -> k.n)),
  (aux decrypt_blinded_unsafe (fun k -> k.n))

let encrypt ~key cs = to_cstruct (encrypt_z ~key (of_cstruct cs))
let decrypt ~key cs = to_cstruct (decrypt_z ~key (of_cstruct cs))


(* XXX proper rng *)
let random_z bytes =
  let rec loop acc = function
    | 0 -> acc
    | n ->
        let i = Random.int 0x100 in
        loop Z.((shift_left acc 8) lor of_int i) (pred n) in
  loop Z.zero bytes

(* XXX
 * This is fishy. Most significant bit is always set to avoid reducing the
 * modulus, but this drops 1 bit of randomness. Investigate.
 *)
let rec gen_prime_z ?mix bytes =
  let lead = match mix with
    | Some x -> x
    | None   -> Z.(pow (of_int 2)) (bytes * 8 - 1) in
  let z = Z.(random_z bytes lor lead) in
  match Z.probab_prime z 25 with
  | 0 -> gen_prime_z ~mix:lead bytes
  | _ -> z

(* XXX
 * All kinds bad. Default public exponent should probably be smaller than
 * 2^16+1. Works only for key sizes of 2n bytes. Two bits of that are rigged.
 *)
let generate ?(e = Z.of_int 0x10001) bytes =

  let (p, q) =
    let rec attempt order =
      let (p, q) = (gen_prime_z order, gen_prime_z order) in
      match p = q with
      | false when Z.(gcd e (pred p) = one) &&
                   Z.(gcd e (pred q) = one) -> (p, q)
      | _                                   -> attempt order in
    attempt (bytes / 2)
  in
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


let attempt =
  let e = Z.of_int 43
  and m = Cstruct.of_string "quasyantistatic hemoglobin" in
(*   and m = Cstruct.of_string "AB" in *)
  fun () ->
    Printf.printf "+ generating...\n%!";
    let key = generate 64 in
(*     let key = generate 2 in *)
    print_key key;
    Printf.printf "+ encrypt...\n%!";
    let c = encrypt ~key:(pub_of_priv key) m in
    Cstruct.hexdump c;
    Printf.printf "+ decrypt...\n%!";
    let m'  = decrypt ~key c in
    assert (m = m')

