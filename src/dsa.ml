open Sexplib.Conv
open Uncommon

(* good values for l,n are: (1024, 160) (2048, 224) (2048, 256) (3072, 256) *)

type pub = { p : Z.t ; q : Z.t ; g : Z.t ; y : Z.t } with sexp
type priv = { p : Z.t ; q : Z.t ; g : Z.t ; x : Z.t ; y : Z.t } with sexp

let pub ~p ~q ~g ~y =
  Numeric.Z.({
    p = of_cstruct_be p ;
    q = of_cstruct_be q ;
    g = of_cstruct_be g ;
    y = of_cstruct_be y ;
  })

let priv ~p ~q ~g ~x ~y =
  Numeric.Z.({
    p = of_cstruct_be p ;
    q = of_cstruct_be q ;
    g = of_cstruct_be g ;
    x = of_cstruct_be x ;
    y = of_cstruct_be y ;
  })

let pub_of_priv { p; q; g; x; y } = { p; q; g; y }

(* XXX: This does not work yet...
let gen_probable_primes l n =
  (* XXX: hash should actually be SHA512/224 or SHA512/256
    (other IV and truncated to 224/256 bits output) *)
  (* this is FIPS 186 A.1.1.2 -- generation of the probable prime p and q using an approved hash function *)
  let outlen = n in
  let seedlen = n in
  let n' = cdiv l outlen - 1 in
  let b = l - 1 - (n' * outlen) in
  let rec attempt () =
    let rand = Rng.generate (cdiv seedlen 8) in
    let twon =
      let n = n - 1 in
      Z.(shift_left one n)
    in
    let u =
      let d = Numeric.Z.of_cstruct_be (Hash.digest `SHA512 rand) in
      Z.(d mod twon)
    in
    let q = Z.(twon + u + one - (u mod (succ one))) in
    (* test whether q is prime! *)
    if Z.probab_prime q 10 = 0 then
      attempt ()
    else
      let rec makep offset counter =
        if counter >= 4 * l then
          attempt ()
        else
          let rec random acc = function
            | x when x < 512 ->
               let last = Hash.digest `SHA512 (Rng.generate (cdiv seedlen 8)) in
               Cs.concat ((Cstruct.sub last 0 (cdiv x 8)) :: acc)
            | x -> random (Hash.digest `SHA512 (Rng.generate (cdiv seedlen 8)) :: acc) (x - 512) (* actually rand + offset + j *)
          in
          let w = Numeric.Z.of_cstruct_be (random [] outlen) in
          let lp =
            let pl = l - 1 in
            Z.(shift_left one pl)
          in
          let x = Z.(w + lp) in
          let c = Z.(x mod (two * q)) in
          let p = Z.(x - (pred c)) in
          if p < lp then
            makep (offset + n' + 1) (counter + 1)
          else
            if Z.probab_prime p 10 > 0 then
              (p, q)
            else
              makep (offset + n' + 1) (counter + 1)
      in
      makep 1 0
  in
  attempt ()

let gen_generator p q =
  (* this is A.2.1 from FIPS-186 *)
  let e = Z.(div (p - one) q) in
  let rec attempt () =
    let h = Z.succ (Rng.Z.gen_r Z.one p) in (* 1 < h < p - 1 *)
    let g = Z.(powm h e p) in
    if g = Z.one then
      attempt ()
    else
      g
  in
  attempt ()

let gen_key_pair p q g =
  let c = Rng.Z.gen_r Z.one q in
  let x = Z.(succ (c mod (pred q))) in
  let y = Z.(powm g x p) in
  (x, y)
 *)

let generate l n =
(*  let p, q = gen_probable_primes l n in
  let g = gen_generator p q in
  let x, y = gen_key_pair p q g in
  { p; q; g; x; y } *)
  assert false


let gen_k p q g =
  let c = Rng.Z.gen_r Z.one q in
  Z.(c mod (q - Z.one) + one)

type mask = [ | `No | `Yes ]

let sign_ { p; q; g; x; _ } k inv_k m =
  let r = Z.((powm g k p) mod q) in
  let s = Z.(inv_k * (m + x * r) mod q) in
  if r = Z.zero || s = Z.zero then
    None
  else
    Some (r, s)

let sign ~key:({ p; q; g; x; _ } as priv) ?(mask = `Yes) ?k ~hash m =
  let size = cdiv (Numeric.Z.bits q) 8 in
  let hashbytes = min size (Hash.digest_size hash) in
  let hm = Hash.digest hash m in
  let hm = Cstruct.sub hm 0 hashbytes in
  let hm = Numeric.Z.of_cstruct_be hm in
  let rec tryme () =
    let k = match k with
      | Some k -> Numeric.Z.of_cstruct_be k
      | None -> gen_k p q g
    in
    let key, k, inv_k, hm =
      match mask with
      | `No  -> (priv, k, Z.(invert k q), hm)
      | `Yes -> let blind = Rng.Z.gen_r Z.one q in
                ({ priv with x = Z.(x * blind) }, k, Z.(invert (blind * k) q), Z.(hm * blind))
    in
    match sign_ key k inv_k hm with
    | None -> tryme ()
    | Some (r, s) -> Numeric.Z.(to_cstruct_be ~size r, to_cstruct_be ~size s)
  in
  tryme ()

let verify ~key:({ p ; q ; g ; y } : pub) ~hash m (r, s) =
  let r = Numeric.Z.of_cstruct_be r
  and s = Numeric.Z.of_cstruct_be s
  and hashbytes = min (Hash.digest_size hash) (cdiv (Numeric.Z.bits q) 8)
  in
  let hm = Hash.digest hash m in
  let hm = Cstruct.sub hm 0 hashbytes in
  let hm = Numeric.Z.of_cstruct_be hm in
  if r > Z.zero && s > Z.zero && r < q && s < q then
    let w = Z.(invert s q) in
    let u1 = Z.(hm * w mod q) in
    let u2 = Z.(r * w mod q) in
    let v = Z.(((powm g u1 p * powm y u2 p) mod p) mod q) in
    if v = r then
      true
    else
      false
  else
    false

