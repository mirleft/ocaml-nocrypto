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

    (* xxx *)
    let test_loop1 bound =
      let x = gen bound in
      Printf.printf "- %s\n%!" N.(to_string x) ;
      assert (N.of_cstruct (N.to_cstruct x) = x)

    let test_loop2 bytes =
      let cs = Rng.generate bytes in
      Cstruct.hexdump cs ;
      assert (N.to_cstruct (N.of_cstruct cs) = cs)
  end

  module Int   = N_gen (Numeric.Int  )
  module Int32 = N_gen (Numeric.Int32)
  module Int64 = N_gen (Numeric.Int64)
  module Z     = N_gen (Numeric.Z    )

  let generate = Rng.generate

end

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

