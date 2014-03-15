
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


(* XXX
 * This is fishy. Most significant bit is always set to avoid reducing the
 * modulus, but this drops 1 bit of randomness. Investigate.
 *)
let rec gen_prime_z ?mix bytes =
  let lead = match mix with
    | Some x -> x
    | None   -> Z.(pow (of_int 2)) (bytes * 8 - 1) in
  let z = Z.(Rng.gen_z_bytes bytes lor lead) in
(*   Z.nextprime z *)
  match Z.probab_prime z 25 with
  | 0 -> gen_prime_z ~mix:lead bytes
  | _ -> z

(* XXX
 * All kinds bad. Default public exponent should probably be smaller than
 * 2^16+1. Works only for key sizes of 2n bytes. Two bits of that are rigged.
 *)
let generate ?(e = Z.of_int 0x10001) bytes =

  Printf.printf "DON'T use this to generate actualy keys.\n%!";

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



(* debug crap *)

let attempt =
(*   let m = Cstruct.of_string "quasyantistatic hemoglobin" in *)
  let m = Cstruct.of_string "AB" in
  fun () ->
    Printf.printf "+ generating...\n%!";
(*     let key = generate 384 in *)
(*     let key = generate 64 in *)
    let key = generate ~e:(Z.of_int 3) 2 in
    print_key key;
    Printf.printf "+ encrypt...\n%!";
    let c = encrypt ~key:(pub_of_priv key) m in
    Cstruct.hexdump c;
    Printf.printf "+ decrypt...\n%!";
    let m'  = decrypt ~key c in
    assert (m = m')

let rec rspan ?(times = 1000) sp =
  let rec loop sum = function
    | 0 -> Some sum
    | n ->
        match Rng.gen_z Z.zero sp with
        | x when x < sp -> loop Z.(sum + x) (pred n)
        | _             -> None in
  match loop Z.zero times with
  | Some s ->
      let avg = Z.(s / of_int times) in
      let dev = Z.(abs (sp / of_int 2 - avg)) in
      Printf.printf "neat: range: %s avg: %s delta: %s\n%!"
        Z.(to_string sp) Z.(to_string avg) Z.(to_string dev)
  | None -> failwith "oops."

