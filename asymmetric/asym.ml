open Nocrypto
open Nocrypto.Uncommon

let kasprintf k fmt =
  Format.(kfprintf (fun _ -> k (flush_str_formatter ())) str_formatter fmt)

let invalid_arg fmt = kasprintf invalid_arg ("Nocrypto_asymmetric: " ^^ fmt)
let failwith fmt = kasprintf failwith ("Nocrypto_asymmetric: " ^^ fmt)

let (&.) f g = fun h -> f (g h)

let rec until p f = let r = f () in if p r then r else until p f

let imin (a : int) b = if a < b then a else b
let imax (a : int) b = if a < b then b else a

let iter2 a b   f = f a; f b
let iter3 a b c f = f a; f b; f c

module List = struct
  include List
  let find_opt p xs = try Some (find p xs) with Not_found -> None
end

(* The Sexplib hack... *)
module Z = struct
  include Z

  let two   = ~$2
  let three = ~$3

  let pp = pp_print

  open Sexplib.Conv
  let sexp_of_t z = sexp_of_string (Z.to_string z)
  let t_of_sexp s = Z.of_string (string_of_sexp s)
end

module ZNumeric = struct
  module Z0 = Z

  module Z_core = struct
    let bit_bound z = Z.size z * 64
    include Z
    let (lsr) = shift_right
    let (lsl) = shift_left
  end

  module Z     = Numeric.Make_S (Z_core    )

  (* Handbook of Applied Cryptography, Table 4.4:
   * Miller-Rabin rounds for composite probability <= 1/2^80. *)
  let pseudoprime z =
    let i = match Z.bits z with
      | i when i >= 1300 ->  2
      | i when i >=  850 ->  3
      | i when i >=  650 ->  4
      | i when i >=  350 ->  8
      | i when i >=  250 -> 12
      | i when i >=  150 -> 18
      | _                -> 27 in
    Z0.probab_prime z i <> 0

  (* strip_factor ~f x = (s, t), where x = f^s t *)
  let strip_factor ~f x =
    let rec go n x =
      let (x1, r) = Z0.div_rem x f in
      if r = Z0.zero then go (succ n) x1 else (n, x) in
    if Z0.two <= f then go 0 x else invalid_arg "factor_count: f: %a" Z0.pp f
end

module ZRng = struct
  module ZN    = Rng.Make_N (ZNumeric.Z)

  (* Invalid combinations of ~bits and ~msb will loop forever, but there is no
   * way to quickly determine upfront whether there are any primes in the
   * interval.
   * XXX Probability is distributed as inter-prime gaps. So?
  *)
  let rec prime ?g ?(msb = 1) bits =
    let p = Z.(nextprime @@ ZN.gen_bits ?g ~msb bits) in
    if p < Z.(one lsl bits) then p else prime ?g ~msb bits

  (* XXX Add ~msb param for p? *)
  let rec safe_prime ?g bits =
    let q = prime ?g ~msb:1 (bits - 1) in
    let p = Z.(q * ~$2 + ~$1) in
    if ZNumeric.pseudoprime p then (q, p) else safe_prime ?g bits

  (*     |+ Pocklington primality test specialized for `a = 2`. +|
         if Z.(gcd (of_int 3) p = one) then (q, p)
         else safe_prime ?g ~bits *)
  module Z = ZN

end
