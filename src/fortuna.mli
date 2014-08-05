(** Implementation of {{: https://www.schneier.com/fortuna.html} Fortuna} CSPRNG.  *)

type g
(** Generator state. Changes when operated upon. *)

exception Unseeded_generator
(** Thrown when using an uninitialized {!g}. *)

val block_size : int
(** Internally, generation always produces a multiple of [block_size] bytes. *)

val create : unit -> g
(** Create new, unseeded {!g}. *)
val clone  : g:g -> g
(** Clone a generator in its current state. *)
val seeded : g:g -> bool
(** [seeded ~g] is [true] iff operations won't throw {!Unseeded_generator}. *)

val reseed   : g:g -> Cstruct.t -> unit
(** [reseed ~g bytes] updates [g] by mixing in [bytes] which should be unpredictable and ideally environmentally sourced. *)
val reseedv  : g:g -> Cstruct.t list -> unit
(** [reseedv ~g list] is like [reseed] with a concatenation of [list], but faster. *)
val generate : g:g -> int -> Cstruct.t
(** [generate ~g n] extracts [n] bytes of random stream from [g]. *)

module Accumulator : sig
  (**
    Accumulator pools, collecting entropy and periodically reseeding the
    attached {!g}.

    Reseeding is performed on the first {!generate} following a non-empty
    sequence of calls to {!add}.

    Each accumulator instance contains 32 entropy pools, which are taken into
    account with exponentially decreasing frequency and are meant to be fed
    round-robin.
  *)

  type t
  (** An accumulator. *)
  val create : g:g -> t
  (** Creates a new accumulator feeding into [g]. *)
  val add : acc:t -> source:int -> pool:int -> Cstruct.t -> unit
  (** [add ~acc ~source ~pool bytes] adds bytes into [pool]-th entropy pool of
    the accumulator [acc], marked as coming from [source]. [pool] is taken
    [mod 32] and [source] is taken [mod 256].
    This operation is fast and is expected to be frequently called with small
    amounts of environmentally sourced entropy, such as timings or user input.
    [source] should indicate a stable source of input but has no meaning beyond
    that. [pool]s should be rotated roughly round-robin.
  *)
  val add_rr : acc:t -> (source:int -> Cstruct.t -> unit)
  (** [add_rr ~acc] is [fun], where each successive call to [fun ~source bytes]
   performs [add] with the next pool in [acc], in a round-robin fashion. *)

end
