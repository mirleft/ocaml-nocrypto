
type g
exception Unseeded_generator

val block_size : int

val create : unit -> g
val clone  : g:g -> g
val seeded : g:g -> bool

val reseedv  : g:g -> Cstruct.t list -> unit
val reseed   : g:g -> Cstruct.t      -> unit
val generate : g:g -> int            -> Cstruct.t

module Accumulator : sig
  type t
  val create : g:g   -> t
  val add    : acc:t -> src:int -> pool:int -> Cstruct.t -> unit
  val add_rr : acc:t -> (src:int -> Cstruct.t -> unit)
end
