
open Algo_types.Rand

module Numeric_of : functor (Rng : Rng) -> Numeric
  with module Rng = Rng

module Def_rng : Rng

include Numeric with module Rng = Def_rng
include Rng with type g = Def_rng.g

val reseed  : Cstruct.t      -> unit
val reseedv : Cstruct.t list -> unit

module Accumulator : sig
  val add    : src:int -> pool:int -> Cstruct.t -> unit
  val add_rr : src:int -> Cstruct.t -> unit
end
