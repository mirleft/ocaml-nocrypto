(** {1 Randomness} *)

(** Secure random number generation.

    There are several parts of this module:

    {ul
    {- The {{!Rng.S.Generator}signature} of generator modules, together with a
       facility to convert such modules into actual {{!g}generators}, and
       functions that operate on this representation.}
    {- A global generator instance, implemented by
       {{!Rng.Generators.Fortuna}Fortuna}.  This is the default generator, used
       when one is not explicitly supplied.}
    {- The {{!S.N}signature} of modules for randomly generating a particular
       numeric type, a {{!Rng.Make_N}functor} to produce them, and instances for
       {{!Rng.Int}[int]}, {{!Rng.Int32}[int32]}, {{!Rng.Int64}[int64]}, and
       {{!Rng.Z}[Z.t]}.}
    {- Several specialized functions for e.g. primes.}}
*)

(** {1 Usage notes} *)

(** {b TL;DR} Don't forget to seed; don't maintain your own [g].

    The RNGs here are merely the deterministic part of a full random number
    generation suite. For proper operation, they need to be seeded with a
    high-quality entropy source.

    Suitable entropy sources are provided by sub-libraries
    {{!Nocrypto_entropy_unix}nocrypto.unix}, {{!Nocrypto_entropy_lwt}nocrypto.lwt}
    and {{!Nocrypto_entropy_mirage}nocrypto.xen}. Although this module exposes a more
    fine-grained interface, allowing manual seeding of generators, this is intended
    either for implementing entropy-harvesting modules, or very specialized
    purposes. Users of this library should almost certainly use one of the above
    entropy libraries, and avoid manually managing the generator seeding.

    Similarly, although it is possible to swap the default generator and gain
    control over the random stream, this is also intended for specialized
    applications such as testing or similar scenarios where the RNG needs to be
    fully deterministic, or as a component of deterministic algorithms which
    internally rely on pseudorandom streams.

    In the general case, users should not maintain their local instances of
    {{!g}g}. All of the generators in a process have to compete for entropy, and
    it is likely that the overall result will have lower effective
    unpredictability.

    The recommended way to use these functions is either to accept an optional
    generator and pass it down, or to ignore the generator altogether, as
    illustrated in the {{!rng_examples}examples}.
*)

type bits = int

(** {1 Interface} *)

type g
(** A generator (PRNG) with its state. *)

exception Unseeded_generator
(** Thrown when using an uninitialized {{!g}generator}. *)

(** Module signatures. *)
module S : sig

  (** A single PRNG algorithm. *)
  module type Generator = sig

    type g
    (** State type for this generator. *)

    val block : int
    (** Internally, this generator's {{!generate}generate} always produces
        [k * block] bytes. *)

    val create : unit -> g
    (** Create a new, unseeded {{!g}g}. *)

    val generate : g:g -> int -> Cstruct.t
    (** [generate ~g n] produces [n] uniformly distributed random bytes,
        updating the state of [g]. *)

    val reseed : g:g -> Cstruct.t -> unit
    (** [reseed ~g bytes] directly updates [g]. Its new state depends both on
        [bytes] and the previous state.

        A generator is seded after a single application of [reseed]. *)

    val accumulate : g:g -> [`Acc of source:int -> Cstruct.t -> unit]
    (** [accumulate ~g] is a closure suitable for incrementally feeding
        small amounts of environmentally sourced entropy into [g].

        Its operation should be fast enough for repeated calling from e.g.
        event loops. Systems with several distinct, stable entropy sources
        should use stable [source] to distinguish their sources.

        A generator is seeded after a single application of the closure. *)

    val seeded : g:g -> bool
    (** [seeded ~g] is [true] iff operations won't throw
        {{!Unseeded_generator}Unseeded_generator}. *)
  end

  (* XXX *)
  type 'a generator = (module Generator with type g = 'a)
end

(** Ready-to-use RNG algorithms. *)
module Generators : sig

  (** {b Fortuna}, a CSPRNG {{: https://www.schneier.com/fortuna.html} proposed}
      by Schneier. *)
  module Fortuna : S.Generator

  (** {b HMAC_DRBG}: A NIST-specified RNG based on HMAC construction over the
      provided hash. *)
  module Hmac_drgb : sig
    module Make (H : Nocrypto_hash.S) : S.Generator
  end

  (** No-op generator returning exactly the bytes it was seeded with. *)
  module Null : S.Generator
end


val create : ?g:'a -> ?seed:Cstruct.t -> ?strict:bool -> (module S.Generator with type g = 'a) -> g
(** [create module] uses a module conforming to the {{!S.Generator}Generator}
    signature to instantiate the generic generator {{!g}g}.

    [g] is the state to use, otherwise a fresh one is created.

    [seed] can be provided to immediately reseed the generator with.

    [strict] puts the generator into a more standards-conformant, but slighty
    slower mode. Useful if the outputs need to match published test-vectors. *)

val generator : g ref
(** Default generator. Functions in this module use this generator when not
    explicitly supplied one.

    Swapping the [generator] is a way to subvert the random-generation process
    e.g. to make it fully deterministic.

    [generator] defaults to {{!Generators.Fortuna}Fortuna}. *)

val generate : ?g:g -> int -> Cstruct.t
(** Invoke {{!S.Generator.generate}generate} on [g] or
    {{!generator}default generator}. *)

val block : g option -> int
(** {{!S.Generator.block}Block} size of [g] or
    {{!generator}default generator}. *)

(**/**)

(* The following functions expose the seeding interface. They are meant to
  * connect the RNG with entropy-providing libraries and subject to change.
  * Client applications should not use them directly. *)

val reseed     : ?g:g -> Cstruct.t -> unit
val accumulate : g option -> [`Acc of source:int -> Cstruct.t -> unit]
val seeded     : g option -> bool
(**/**)


(** {1 Generation of common numeric types} *)

(** Typed generation of a particular numeric type. *)
module type Arith = sig

  type t
  (** The type of extracted values. *)

  val gen : ?g:g -> t -> t
  (** [gen ~g n] picks a value in the interval [\[0, n - 1\]] uniformly at random. *)

  val gen_r : ?g:g -> t -> t -> t
  (** [gen_r ~g low high] picks a value from the interval [\[low, high - 1\]]
      uniformly at random. *)

  val gen_bits : ?g:g -> ?msb:bits -> bits -> t
  (** [gen_bits ~g ~msb n] picks a bit-string [n] bits long, with [msb] most
      significant bits set, and interprets it as a {{!t}t} in big-endidan.
      This yields a value in the interval
      [\[2^(n-1) + ... + 2^(n-msb), 2^n - 1\]].

      [msb] defaults to [0] which reduces [gen_bits k] to [gen 2^k]. *)
end

module Int   : Arith with type t = int
module Int32 : Arith with type t = int32
module Int64 : Arith with type t = int64

module type Number = sig
  type t
  val zero : t
  val one : t
  val bit_size : t -> int
  val of_cstruct_be : bits:bits -> Cstruct.t -> t
  val pp : Format.formatter -> t -> unit
  val (+) : t -> t -> t
  val (-) : t -> t -> t
end

module Arith (N: Number): Arith with type t = N.t
(** Creates a suite of generating functions over a numeric type. *)

(**/**)

module Private : sig
  val of_cstruct_be   : bits:int -> Cstruct.t -> int
  val of_cstruct_be32 : bits:int -> Cstruct.t -> int32
  val of_cstruct_be64 : bits:int -> Cstruct.t -> int64
  val bit_size   : int -> int
  val bit_size32 : int32 -> int
  val bit_size64 : int64 -> int
end
(**/**)

(** {1:rng_examples Examples}

    Generating a random 13-byte {!Cstruct.t}:
{[let cs = Rng.generate 13]}

    Generating a list of {!Cstruct.t}s, passing down an optional
    {{!g}generator}:
{[let rec f1 ?g ~n i =
  if i < 1 then [] else Rng.generate ?g n :: f1 ?g ~n (i - 1)]}

    Generating a [Z.t] smaller than [10] and an [int64] in the range [\[3, 7\]]:
{[let f2 ?g () = Rng.(Z.gen ?g ~$10, Int64.gen_r 3L 8L)]}

    Creating a local Fortuna instance and using it as a key-derivation function:
{[let f3 secret =
  let g = Rng.(create ~seed:secret (module Generators.Fortuna)) in
  Rng.generate ~g 32]}

    Generating a 17-bit prime with two leading bits set:
{[let p = Rng.prime ~msb:2 17]}

    Fisher-Yates shuffle:
{[let f4 ?g arr =
  let n = Array.length arr in
  arr |> Array.iter @@ fun i ->
    let j = Rng.Int.gen_r ?g i n in
    let (a, b) = (arr.(i), arr.(j)) in
    arr.(i) <- b ; arr.(j) <- a ]}
      *)
