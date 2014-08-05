
open Algo_types

module Numeric_of :
  functor (Rng : Rand.Rng) -> Rand.Numeric with type g = Rng.g

type g = Fortuna.g

include Rand.Rng     with type g := g
include Rand.Numeric with type g := g

val reseed  : Cstruct.t      -> unit
val reseedv : Cstruct.t list -> unit
val seeded  : unit           -> bool
val set_gen : g:g            -> unit

module Accumulator : sig
  val add    : source:int -> pool:int -> Cstruct.t -> unit
  val add_rr : source:int -> Cstruct.t -> unit
end
