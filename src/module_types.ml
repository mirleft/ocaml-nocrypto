
module Random = struct
  (** Module types connected to random number generation. *)

  module type Rng = sig
    (** The core random generator signature. *)

    type g
    (** State type for this generator. *)
    val block_size : int
    (** Internally, this generator's {!generate} always produces [k * block_size] bytes. *)
    val generate : ?g:g -> int -> Cstruct.t
    (** [generate ~g n] produces [n] random bytes, using either the given or a
        default {!g}. *)
  end

  module type N = sig
    (** Typed random number extraction. *)

    type t
    (** The type of extracted values. *)
    type g
    (** Random generator. *)

    val gen : ?g:g -> t -> t
    (** [gen ~g n] picks a value in the interval [\[0, n - 1\]] uniformly at random. *)
    val gen_r : ?g:g -> t -> t -> t
    (** [gen_r ~g low high] picks a value from the interval [\[low, high - 1\]]
        uniformly at random. *)
    val gen_bits : ?g:g -> int -> t
    (** [gen_bits ~g n] picks a value with exactly [n] significant bits,
        uniformly at random. *)
  end

  module type Numeric = sig
    (** A full suite of numeric extractions. *)

    type g
    (** Random generator. *)

    val prime : ?g:g -> ?msb:int -> bits:int -> Z.t
    (** [prime ~g ~msb ~bits] generates a prime smaller than [2^bits], such that
        its [msb] most significant bits are set.
        [prime ~g ~msb:1 ~bits] (the default) yields a prime in the interval
        [\[2^(bits - 1), 2^bits - 1\]]. *)
    val safe_prime : ?g:g -> bits:int -> Z.t * Z.t
    (** [safe_prime ~g ~bits] gives a prime pair [(g, p)] such that [p = 2g + 1]
        and [p] has [bits] significant bits. *)

    module Int   : N with type g = g and type t = int
    module Int32 : N with type g = g and type t = int32
    module Int64 : N with type g = g and type t = int64
    module Z     : N with type g = g and type t = Z.t

    module Fc : sig
      type 'a t = (module N with type g = g and type t = 'a)
      val int   : int   t
      val int32 : int32 t
      val int64 : int64 t
      val z     : Z.t   t
    end

    val strict : bool -> unit
  end

end

module type Basic_hash = sig
  (** A hashing algorithm. *)

  type t (** A changing hashing context. *)

  val digest_size : int (** Size of hashing results, in bytes. *)

  val init : unit -> t (** Create a new hashing context. *)
  val feed : t    -> Cstruct.t -> unit (** Update the context *)
  val get  : t    -> Cstruct.t (** Extract the digest; [t] becomes invalid. *)

  val digest  : Cstruct.t      -> Cstruct.t (** Digest in one go. *)
  val digestv : Cstruct.t list -> Cstruct.t (** Digest in one go. *)
end

module type Hash = sig
  (** A hashing algorithm equipped with HMAC. *)

  include Basic_hash

  val hmac : key:Cstruct.t -> Cstruct.t -> Cstruct.t
  (** [hmac ~key bytes] is authentication code for [bytes] under the secret
      [key], generated using the standard HMAC construction over this hash
      algorithm. *)
end

