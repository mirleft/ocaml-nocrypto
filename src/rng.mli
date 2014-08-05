(** A global instance of {!Fortuna}. *)

open Algo_types

module Numeric_of :
  functor (Rng : Random.Rng) -> Random.Numeric with type g = Rng.g
(** Gives the numeric extraction suite over an {!Random.Rng}. *)

type g = Fortuna.g

include Random.Rng     with type g := g (** Base RNG generation. *)
include Random.Numeric with type g := g (** Numeric RNG generation. *)

val reseed  : Cstruct.t      -> unit
val reseedv : Cstruct.t list -> unit
val seeded  : unit           -> bool
val set_gen : g:g            -> unit

module Accumulator : sig
  val add    : source:int -> pool:int -> Cstruct.t -> unit
  val add_rr : source:int -> Cstruct.t -> unit
end
