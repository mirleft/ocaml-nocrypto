
type pub  = { e : Z.t ; n : Z.t }

type priv = {
  e : Z.t ; d : Z.t ; n  : Z.t ;
  p : Z.t ; q : Z.t ; dp : Z.t ; dq : Z.t ; q' : Z.t
}

let pub ~e ~n = { e ; n }

let priv ~e ~d ~n ~p ~q ~dp ~dq ~q' = { e; d; n; p; q; dp; dq; q' }

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
let decrypt_blinded_unsafe ?g ~key: ({ e; n } as key : priv) c =

  let rec nonce () =
    let x = Rng.Z.gen_r ?g Z.(of_int 2) n in
    if Z.(gcd x n = one) then x else nonce () in

  let r  = nonce () in
  Printf.printf "blind: nonce: %s\n%!" (Z.to_string r) ;

  let r' = Z.(invert r n) and re = Z.(powm r e n) in
  let x  = decrypt_unsafe ~key Z.((re * c) mod n) in
  Z.((r' * x) mod n)


let (encrypt_z, decrypt_z) =
  let check_params n msg =
    if msg >= n then invalid_arg "RSA: key too small" ;
    if msg < Z.one then invalid_arg "RSA: non-positive message"
  in
  (fun    ~(key : pub ) msg ->
    check_params key.n msg ; encrypt_unsafe ~key msg),
  (fun ?g ~(key : priv) msg ->
    check_params key.n msg ; decrypt_blinded_unsafe ?g ~key msg)

let encrypt    ~key cs = Numeric.Z.(to_cstruct @@ encrypt_z    ~key (of_cstruct cs))
let decrypt ?g ~key cs = Numeric.Z.(to_cstruct @@ decrypt_z ?g ~key (of_cstruct cs))


(* XXX
 * This is fishy. Most significant bit is always set to avoid reducing the
 * modulus, but this drops 1 bit of randomness. Investigate.
 *)
let rec random_prime ?g ?mix bits =
  let lead = match mix with
    | Some x -> x
    | None   -> Z.(pow (of_int 2)) (bits - 1) in
  let z = Z.(Rng.Z.gen_bits ?g bits lor lead) in
(*   Z.nextprime z *)
  match Z.probab_prime z 25 with
  | 0 -> random_prime ?g ~mix:lead bits
  | _ -> z

(* XXX
 * All kinds bad. Default public exponent should probably be smaller than
 * 2^16+1. Two bits of key are rigged.
 *)
let generate ?g ?(e = Z.of_int 0x10001) bits =

  Printf.printf "DON'T use this to generate actual keys.\n%!";

  let (p, q) =
    let rec attempt bits =
      (* xxx *)
      let (p, q) = (random_prime ?g bits, random_prime ?g bits) in
      match p = q with
      | false when Z.(gcd e (pred p) = one) &&
                   Z.(gcd e (pred q) = one) -> (p, q)
      | _                                   -> attempt bits in
    attempt (bits / 2)
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



(* debug crap *)

let attempt =
(*   let m = Cstruct.of_string "quasyantistatic hemoglobin" in *)
  let m = Cstruct.of_string "AB" in
  fun () ->
    Printf.printf "+ generating...\n%!";
(*     let key = generate 3072 in *)
(*     let key = generate 512 in *)
    let key = generate ~e:(Z.of_int 3) 16 in
    print_key key;
    Printf.printf "+ encrypt...\n%!";
    let c = encrypt ~key:(pub_of_priv key) m in
    Cstruct.hexdump c;
    Printf.printf "+ decrypt...\n%!";
    let m'  = decrypt ~key c in
    assert (m = m')

(* let rec rspan ?(times = 1000) sp =
  let rec loop sum = function
    | 0 -> Some sum
    | n ->
        match Z.zero with
|+         match Rng.gen_z Z.zero sp with +|
        | x when x < sp -> loop Z.(sum + x) (pred n)
        | _             -> None in
  match loop Z.zero times with
  | Some s ->
      let avg = Z.(s / of_int times) in
      let dev = Z.(abs (sp / of_int 2 - avg)) in
      Printf.printf "neat: range: %s avg: %s delta: %s\n%!"
        Z.(to_string sp) Z.(to_string avg) Z.(to_string dev)
  | None -> failwith "oops." *)

