
open Algo_types.Rand
open Common

module Numeric_of (Rng : Rng) = struct

  module Rng = Rng

  module N_gen (N : Numeric.T) = struct

    type t = N.t
    type g = Rng.g

    let gen ?g n =
      if n < N.one then invalid_arg "rng: non-positive bound" ;

      let size   = N.bits (N.pred n) in
      let octets = cdiv size 8 in
      (* Generating octets * 4 makes ~94% cases covered in a single run. *)
      let batch  = Rng.(block_size * cdiv (octets * 4) block_size) in

      let rec attempt cs =
        try
          let x = N.of_bits_be cs size in
          if x < n then x else attempt (Cstruct.shift cs octets)
        with | Invalid_argument _ -> attempt Rng.(generate ?g batch) in
      attempt Rng.(generate ?g batch)

    let gen_r ?g a b = N.(a + gen ?g (b - a))

    let gen_bits ?g bits =

      let octets = cdiv bits 8 in
      let cs     = Rng.(generate ?g octets) in
      N.of_bits_be cs bits
  end

  module Int   = N_gen (Numeric.Int  )
  module Int32 = N_gen (Numeric.Int32)
  module Int64 = N_gen (Numeric.Int64)
  module ZN    = N_gen (Numeric.Z    )

  (* XXX
  * This is fishy. Most significant bit is always set to avoid reducing moduli,
  * but this drops 1 bit of randomness. Investigate.
  *)

  let prime ?g ~bits =
    if bits < 2 then invalid_arg "Rng.prime: < 2 bits" ;

    let limit = Z.(pow z_two) bits
    and mask  = Z.(pow z_two) (bits - 1) in

    let rec attempt () =
      let p = Z.(ZN.gen_bits ?g bits lor mask) in
      match Z.probab_prime p 25 with
      | 0 ->
        ( match Z.nextprime p with
          | p' when p' < limit -> p'
          | _                  -> attempt () )
      | _ -> p in
    attempt ()

  let rec safe_prime ?g ~bits =
    let gg = prime ?g ~bits:(bits - 1) in
    let p  = Z.(gg * z_two + one) in
    match Z.probab_prime p 25 with
    | 0 -> safe_prime ?g ~bits
    | _ -> (gg, p)

(*     |+ Pocklington primality test specialized for `a = 2`. +|
    if Z.(gcd (of_int 3) p = one) then (gg, p)
    else safe_prime ?g ~bits *)

  module Z = ZN

end

module Def_rng = struct
  open Fortuna

  type g = Fortuna.g

  let g = ref (create ())
  let reseedv       = reseedv ~g:!g
  and reseed        = reseed  ~g:!g
  and seeded ()     = seeded  ~g:!g
  and set_gen ~g:g' = g := g'

  let block_size = block_size
  let generate ?(g = !g) n = generate ~g n

  module Accumulator = struct
    open Accumulator
    let acc    = create ~g:!g
    let add    = add    ~acc
    let add_rr = add_rr ~acc
  end
end

module Nums = Numeric_of ( Def_rng )

include Def_rng
include Nums
