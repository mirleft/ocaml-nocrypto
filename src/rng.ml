open Uncommon

module T = struct

  module type Rng = sig
    type g
    val block_size : int
    val generate : ?g:g -> int -> Cstruct.t
  end

  module type N = sig
    type t
    type g

    val gen      : ?g:g -> t -> t
    val gen_r    : ?g:g -> t -> t -> t
    val gen_bits : ?g:g -> ?msb:int -> int -> t
  end

  module type Rng_numeric = sig

    type g

    val prime : ?g:g -> ?msb:int -> int -> Z.t
    val safe_prime : ?g:g -> int -> Z.t * Z.t

    module Int   : N with type g = g and type t = int
    module Int32 : N with type g = g and type t = int32
    module Int64 : N with type g = g and type t = int64
    module Z     : N with type g = g and type t = Z.t

    val strict : bool -> unit
  end
end


module Numeric_of (Rng : T.Rng) = struct

  type g = Rng.g

  let relax = ref true
  let strict s = relax := not s

  module N_gen (N : Numeric.T) = struct

    type t = N.t
    type g = Rng.g

    (* Non-strict: less wasteful in driving the RNG. *)
    let gen_ns ?g n =
      let bits   = N.(bits (pred n)) in
      let octets = cdiv bits 8 in
      let batch  = Rng.(block_size * cdiv (octets * 2) block_size) in

      let rec attempt cs =
        if cs.Cstruct.len >= octets then
          let x = N.of_cstruct_be ~bits cs in
          if x < n then x else attempt (Cstruct.shift cs octets)
        else attempt Rng.(generate ?g batch) in
      attempt Rng.(generate ?g batch)

    let gen_r_ns ?g a b = N.(a + gen_ns ?g (b - a))

    (* Strict: close to how extraction is described in various standards. *)
    let gen_s ?g n =
      let bits   = N.(bits (pred n)) in
      let octets = cdiv bits 8 in
      let rec attempt () =
        let x = N.of_cstruct_be ~bits Rng.(generate ?g octets) in
        if x < n then x else attempt () in
      attempt ()

    let rec gen_r_s ?g a b =
      let x = gen_s ?g b in if x < a then gen_r_s ?g a b else x

    (* Common: reacts to a toggle. The lesser evil... *)
    let gen ?g n =
      if n < N.one then invalid_arg "Rng.gen: non-positive bound";
      (if !relax then gen_ns else gen_s) ?g n

    let gen_r ?g a b =
      (if !relax then gen_r_ns else gen_r_s) ?g a b

    let gen_bits ?g ?(msb = 0) bits =
      let res = Rng.generate ?g (cdiv bits 8) in
      Cs.set_msb msb res ;
      N.of_cstruct_be ~bits res

  end

  module Int   = N_gen (Numeric.Int  )
  module Int32 = N_gen (Numeric.Int32)
  module Int64 = N_gen (Numeric.Int64)
  module ZN    = N_gen (Numeric.Z    )


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
    let gg = prime ?g ~msb:1 (bits - 1) in
    let p  = Z.(gg * two + one) in
    if Numeric.pseudoprime p then (gg, p) else safe_prime ?g bits

(*     |+ Pocklington primality test specialized for `a = 2`. +|
    if Z.(gcd (of_int 3) p = one) then (gg, p)
    else safe_prime ?g ~bits *)

  module Z = ZN

end


type g = Fortuna.g

open Fortuna

let generator = ref (create ())

let reseedv    = reseedv ~g:!generator
and reseed     = reseed  ~g:!generator
and seeded ()  = seeded  ~g:!generator

let block_size = block_size

let generate ?(g = !generator) n = generate ~g n

include ( Numeric_of (
  struct
    type g = Fortuna.g
    let block_size = block_size
    let generate   = generate
  end
) : T.Rng_numeric with type g := g )
