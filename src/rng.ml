open Common
open Algo_types

module Rng_numeric (Rng : Rng) = struct

  module N_gen (N : Numeric.T) = struct

    let gen ?g n =
      if n < N.one then invalid_arg "rng: non-positive bound" ;

      let size   = N.bits (N.pred n) in
      let octets = cdiv size 8 in
      (* Generating octets * 4 makes ~94% cases covered in a single run. *)
      let batch  = Rng.(block * cdiv (octets * 4) block) in

      let rec attempt cs =
        try
          let x = N.of_bits_be cs size in
          if x < n then x else attempt (Cstruct.shift cs octets)
        with | Invalid_argument _ -> attempt Rng.(generate ?g batch) in
      attempt Rng.(generate ?g batch)

    let gen_bits ?g bits =

      let octets = cdiv bits 8 in
      let cs     = Rng.(generate ?g octets) in
      N.of_bits_be cs bits

    let gen_r ?g a b = N.(a + gen ?g (b - a))

  end

  module Z' = Z

  module Int   = N_gen (Numeric.Int  )
  module Int32 = N_gen (Numeric.Int32)
  module Int64 = N_gen (Numeric.Int64)
  module Z     = N_gen (Numeric.Z    )

  (* XXX
  * This is fishy. Most significant bit is always set to avoid reducing the
  * modulus, but this drops 1 bit of randomness. Investigate.
  *)

  let prime ?g bits =
    let limit = Z'.(pow z_two) bits
    and mask  = Z'.(pow z_two) (bits - 1) in
    (* GMP nextprime internally does Miller-Rabin with 25 repetitions, which is
    * good, but we lose the knowledge of whether the number is proven to be
    * prime. *)
    let rec attempt () =
      let p = Z'.(nextprime (Z.gen_bits ?g bits lor mask)) in
      if p < limit then p else attempt () in
    attempt ()

end

type g = Fortuna.g

let g       = Fortuna.create ()
let reseedv = Fortuna.reseedv ~g
and reseed  = Fortuna.reseed  ~g

let generate ?(g = g) n = Fortuna.generate ~g n

module Accumulator = struct
  let acc    = Fortuna.Accumulator.create ~g
  let add    = Fortuna.Accumulator.add    ~acc
  let add_rr = Fortuna.Accumulator.add_rr ~acc
end

module Rng = Rng_numeric ( struct
  type g       = Fortuna.g
  let generate = generate
  let block    = 0x10
end )

include Rng

