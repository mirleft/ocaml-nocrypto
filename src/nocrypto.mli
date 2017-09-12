(** Simpler crypto

    Nocrypto is a cryptographic library.

    The overarching API principle is simply mapping inputs to outputs, wherever
    feasible.

    Similar algorithms in the same class (like {{!Hash}hashes} or
    {{!Cipher_block}block ciphers}) are presented as distinct modules sharing
    the same signature.

    {{!Rng}Randomness} is treated as an ambient effect.

    {e %%VERSION%% — {{:%%PKG_HOMEPAGE%% }homepage}} *)

(*
 * Doc note: Sexplib conversions are noted explicitly instead of using
 * `[@@deriving sexp]` because the syntax extension interacts badly with
 * ocamldoc.
 *)

(** {1 Utilities} *)

(** Base64 conversion.

    It is here only temporary, until we find it a proper home. *)
module Base64 : sig
  val encode : Cstruct.t -> Cstruct.t
  val decode : Cstruct.t -> Cstruct.t option
  val is_base64_char : char -> bool
end


(**/**)

(** A treasure-trove of random utilities.

    This is largely an internal API used in related sub-libraries or tests. As
    such, it is prone to breakage. *)
module Uncommon : sig

  (** ['a one] is just an ['a].

      Useful to break the chain of curried functions when an intermediate
      "partial" application is worth holding onto. *)
  type 'a one = One of 'a

  val cdiv : int -> int -> int
  (** Ceiling division. [cdiv a b] == [ceil(a / b)] *)

  val (&.) : ('b -> 'c) -> ('a -> 'b) -> 'a -> 'c
  (** Function composition. *)

  val id : 'a -> 'a
  (** identity *)

  module Option : sig
    val v_map : def:'b -> f:('a -> 'b) -> 'a option -> 'b
    val map   : f:('a -> 'b) -> 'a option -> 'b option
    val get   : def:'a -> 'a option -> 'a
  end

  (** Addons to {!Cstruct}. *)
  module Cs : sig

    val empty : Cstruct.t
    (** [empty] is an empty [Cstruct]. *)

    val null  : Cstruct.t -> bool
    (** [null cs] tests whether [len cs = 0]. *)

    val (<+>) : Cstruct.t -> Cstruct.t -> Cstruct.t
    (** [<+>] is an alias for [Cstruct.append]. *)

    val ct_eq : Cstruct.t -> Cstruct.t -> bool
    (** Constant-Time [Cstruct.t] equality. *)

    val xor_into : Cstruct.t -> Cstruct.t -> int -> unit
    val xor      : Cstruct.t -> Cstruct.t -> Cstruct.t

    (** {2 Private utilities} *)

    val create : ?init:int -> int -> Cstruct.t
    val clone  : ?off:int -> ?len:int -> Cstruct.t -> Cstruct.t

    val (lsl) : Cstruct.t -> int -> Cstruct.t
    val (lsr) : Cstruct.t -> int -> Cstruct.t

    val of_hex : string -> Cstruct.t
  end

  (** Addons to {!Array}. *)
  module Arr : sig
    val mem : 'a -> 'a array -> bool
  end

  val bracket : init:(unit -> 'a) -> fini:('a -> unit) -> ('a -> 'b) -> 'b
  (** Safe acquire-use-release combinator. *)

end

(**/**)


(** Numeric utilities. *)
module Numeric : sig

  (** Augmented numeric type.
      Includes basic common numeric ops, range of conversions to and from
      variously-sized int types, and a few basic function for representing such
      numbers as {!Cstruct.t}. *)
  module type S = sig

    type t

    val zero : t
    val one  : t

    val (lsr)  : t -> int -> t
    val (lsl)  : t -> int -> t
    val (land) : t -> t -> t
    val (lor)  : t -> t -> t
    val (lxor) : t -> t -> t

    val (+)  : t -> t -> t
    val (-)  : t -> t -> t

    val succ : t -> t
    val pred : t -> t

    val of_int   : int -> t
    val of_int32 : int32 -> t
    val of_int64 : int64 -> t
    val to_int   : t -> int
    val to_int32 : t -> int32
    val to_int64 : t -> int64

    val bit_bound : t -> int

    val pp_print : Format.formatter -> t -> unit

    val bits            : t -> int
    val of_cstruct_be   : ?bits:int -> Cstruct.t -> t
    val to_cstruct_be   : ?size:int -> t -> Cstruct.t
    val into_cstruct_be : t -> Cstruct.t -> unit

  end

  module Int   : S with type t = int
  module Int32 : S with type t = int32
  module Int64 : S with type t = int64
  module Z     : S with type t = Z.t

  (** {1 Misc elementary number theory} *)

  val pseudoprime : Z.t -> bool
  (** Miller-Rabin with sane rounds parameter. *)

end


(** {1 Hashing} *)

(** Hashes.

    Each hash algorithm is contained in its own separate module. *)
module Hash : sig

  (** A single hash algorithm. *)
  module type S = sig

    type t (** Hash state. *)

    val digest_size : int
    (** Size of hash results, in bytes. *)

    val init : unit -> t
    (** Create a new hash state. *)

    val dup : t -> t
    (** Create a deep copy of a hash state. *)

    val feed : t -> Cstruct.t -> unit
    (** Hash the input, updating the state. *)

    val get : t -> Cstruct.t
    (** Extract the digest; state becomes invalid. *)

    val digest  : Cstruct.t -> Cstruct.t
    (** Compute the digest. *)

    val digestv : Cstruct.t list -> Cstruct.t
    (** See {{!digest}[digest]}. *)

    val hmac : key:Cstruct.t -> Cstruct.t -> Cstruct.t
    (** [hmac ~key bytes] is authentication code for [bytes] under the secret
        [key], generated using the standard HMAC construction over this hash
        algorithm. *)

    val hmacv : key:Cstruct.t -> Cstruct.t list -> Cstruct.t
    (** See {{!hmac}[hmac]}. *)
  end

  module MD5     : S
  module SHA1    : S
  module SHA224  : S
  module SHA256  : S
  module SHA384  : S
  module SHA512  : S

  (** {1 Short-hand functions} *)

  type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ]
  (** Hashing algorithm.

      {e [Sexplib] convertible}. *)

  val digest      : [< hash ] -> Cstruct.t -> Cstruct.t
  val digestv     : [< hash ] -> Cstruct.t list -> Cstruct.t
  val mac         : [< hash ] -> key:Cstruct.t -> Cstruct.t -> Cstruct.t
  val macv        : [< hash ] -> key:Cstruct.t -> Cstruct.t list -> Cstruct.t
  val digest_size : [< hash ] -> int
  val module_of   : [< hash ] -> (module S)

  (**/**)
  val hash_of_sexp : Sexplib.Sexp.t -> hash
  val sexp_of_hash : hash -> Sexplib.Sexp.t
  (**/**)

end


(** {1 Symmetric-key cryptography} *)

(** Block ciphers.

    Each algorithm, and each mode of operation, is contained in its own separate
    module. *)
module Cipher_block : sig

  (** Module types for various block cipher modes of operation. *)
  module S : sig

    (** Raw block cipher in all its glory. *)
    module type Core = sig

      type ekey
      type dkey

      val of_secret   : Cstruct.t -> ekey * dkey
      val e_of_secret : Cstruct.t -> ekey
      val d_of_secret : Cstruct.t -> dkey

      val key   : int array
      val block : int

      val encrypt : key:ekey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
      val decrypt : key:dkey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
    end

    (** Modes of operation: *)

    (** {e Electronic Codebook} "mode". *)
    module type ECB = sig

      type key
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val encrypt : key:key -> Cstruct.t -> Cstruct.t
      val decrypt : key:key -> Cstruct.t -> Cstruct.t
    end

    (** {e Cipher-block chaining} mode. *)
    module type CBC = sig

      type key
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int

      val next_iv : iv:Cstruct.t -> Cstruct.t -> Cstruct.t
      (** [next_iv iv ciphertext] for a [ciphertext] and an [iv] it was computed
          with is the iv to use to encrypt the next message, for protocols
          which perform inter-message chaining. It is either the last block of
          [ciphertext] or [iv] if [msg] is too short. *)

      val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
      val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
    end

    (** {e Counter} mode. *)
    module type CTR = sig

      type key
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int

      val stream : key:key -> ctr:Cstruct.t -> ?off:int -> int -> Cstruct.t
      (** [stream ~key ~ctr ~off n] is the first [n] bytes obtained by
          encrypting and concatenating blocks [c(0), c(1), ...], where [c(0)] is
          [ctr], and [c(n + 1)] is [c(n) + 1] interpreted in big-endian.

          If [off] is greater than [0] then the result is the last [n] bytes of
          an [off + n] bytes long stream. Thus,
          [stream ~key ~ctr ~off:0 n || stream ~key ~ctr ~off:n n ==
           stream ~key ~ctr ~off:0 (n*2)].

          [ctr] has to be block-sized, and [off] and [n] need to be
          non-negative. *)

      val encrypt : key:key -> ctr:Cstruct.t -> ?off:int -> Cstruct.t -> Cstruct.t
      (** [encrypt ~key ~ctr ~off msg] is
          [(stream ~key ~ctr ~off (len msg)) xor msg]. *)

      val decrypt : key:key -> ctr:Cstruct.t -> ?off:int -> Cstruct.t -> Cstruct.t
    end

    (** {e Galois/Counter Mode}. *)
    module type GCM = sig
      type key
      type result = { message : Cstruct.t ; tag : Cstruct.t }
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val encrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
      val decrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
    end

    (** {e Counter with CBC-MAC} mode. *)
    module type CCM = sig
      type key
      val of_secret : maclen:int -> Cstruct.t -> key

      val key_sizes  : int array
      val mac_sizes  : int array
      val block_size : int
      val encrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t
      val decrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t option
    end
  end

  (** BE counter function.

      Each [incrX cs i] increments [X]-sized block of [cs] at the offset [i] by
      one, returning [true] if an overfow occurred (and the block is now
      zeroed-out).

      Each [addX cs i n] adds [n] to the [X]-sized block. *)
  module Counter : sig

    val incr1  : Cstruct.t -> int -> bool
    val incr2  : Cstruct.t -> int -> bool
    val incr4  : Cstruct.t -> int -> bool
    val incr8  : Cstruct.t -> int -> bool
    val incr16 : Cstruct.t -> int -> bool

    val add4   : Cstruct.t -> int -> int32 -> unit
    val add8   : Cstruct.t -> int -> int64 -> unit
    val add16  : Cstruct.t -> int -> int64 -> unit
  end

  module AES : sig
    val mode : [ `Generic | `AES_NI ]
(*     module Core : S.Core *)
    module ECB  : S.ECB
    module CBC  : S.CBC
    module CTR  : S.CTR
    module GCM  : S.GCM
    module CCM  : S.CCM
  end

  module DES : sig
(*     module Core : S.Core *)
    module ECB  : S.ECB
    module CBC  : S.CBC
    module CTR  : S.CTR
  end
end


(** Streaming ciphers. *)
module Cipher_stream : sig

  (** General stream cipher type. *)
  module type S = sig
    type key
    type result = { message : Cstruct.t ; key : key }
    val of_secret : Cstruct.t -> key
    val encrypt : key:key -> Cstruct.t -> result
    val decrypt : key:key -> Cstruct.t -> result
  end

  (** {e Alleged Rivest Cipher 4}. *)
  module ARC4 : S
end


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
module Rng : sig

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

      val accumulate : g:g -> (source:int -> Cstruct.t -> unit) Uncommon.one
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

    (** Typed generation of a particular numeric type. *)
    module type N = sig

      type t
      (** The type of extracted values. *)

      val gen : ?g:g -> t -> t
      (** [gen ~g n] picks a value in the interval [\[0, n - 1\]] uniformly at random. *)

      val gen_r : ?g:g -> t -> t -> t
      (** [gen_r ~g low high] picks a value from the interval [\[low, high - 1\]]
          uniformly at random. *)

      val gen_bits : ?g:g -> ?msb:int -> int -> t
      (** [gen_bits ~g ~msb n] picks a bit-string [n] bits long, with [msb] most
          significant bits set, and interprets it as a {{!t}t} in big-endidan.
          This yields a value in the interval
          [\[2^(n-1) + ... + 2^(n-msb), 2^n - 1\]].

          [msb] defaults to [0] which reduces [gen_bits k] to [gen 2^k]. *)
    end

  end

  (** Ready-to-use RNG algorithms. *)
  module Generators : sig

    (** {b Fortuna}, a CSPRNG {{: https://www.schneier.com/fortuna.html} proposed}
        by Schneier. *)
    module Fortuna : S.Generator

    (** {b HMAC_DRBG}: A NIST-specified RNG based on HMAC construction over the
        provided hash. *)
    module Hmac_drgb : sig
      module Make (H : Hash.S) : S.Generator
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
  val accumulate : g option -> (source:int -> Cstruct.t -> unit) Uncommon.one
  val seeded     : g option -> bool
  (**/**)


  (** {1 Generation of common numeric types} *)

  module Make_N (N : Numeric.S) : S.N with type t = N.t
  (** Creates a suite of generating functions over a numeric type. *)

  module Int   : S.N with type t = int
  module Int32 : S.N with type t = int32
  module Int64 : S.N with type t = int64
  module Z     : S.N with type t = Z.t


  (** {1 Specialized generation} *)

  val prime : ?g:g -> ?msb:int -> int -> Z.t
  (** [prime ~g ~msb bits] generates a prime smaller than [2^bits], with [msb]
      most significant bits set.

      [prime ~g ~msb:1 bits] (the default) yields a prime in the interval
      [\[2^(bits - 1), 2^bits - 1\]]. *)

  val safe_prime : ?g:g -> int -> Z.t * Z.t
  (** [safe_prime ~g bits] gives a prime pair [(g, p)] such that [p = 2g + 1]
      and [p] has [bits] significant bits. *)

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

  type buffer = Cstruct.t
  (** Type definition to satisfy MirageOS RANDOM signature *)
end


(** {1 Public-key cryptography} *)

(** {b RSA} public-key cryptography.

Keys are taken to be trusted material, and their properties are not checked.

Messages are checked not to exceed the key size, and this is signalled via
exceptions.

Private-key operations are optionally protected through RSA blinding.
*)
module Rsa : sig

  (** {1 RSA public-key encryption} *)

  exception Insufficient_key
  (** Raised if the key is too small to transform the given message, i.e. if the
      numerical interpretation of the (potentially padded) message is not
      smaller than the modulus.

      It is additionally raised if the message is [0] and the mode does not
      involve padding. *)

  type pub  = {
    e : Z.t ; (** Public exponent *)
    n : Z.t ; (** Modulus *)
  }
  (** Public key.

      {e [Sexplib] convertible}. *)

  type priv = {
    e  : Z.t ; (** Public exponent *)
    d  : Z.t ; (** Private exponent *)
    n  : Z.t ; (** Modulus *)
    p  : Z.t ; (** Prime factor [p] *)
    q  : Z.t ; (** Prime factor [q] *)
    dp : Z.t ; (** [d mod (p-1)] *)
    dq : Z.t ; (** [d mod (q-1)] *)
    q' : Z.t ; (** [q^(-1) mod p] *)
  }
  (** Private key (two-factor version).

      {e [Sexplib] convertible}. *)

  type mask = [ `No | `Yes | `Yes_with of Rng.g ]
  (** Masking (cryptographic blinding) option. *)

  val pub_bits : pub -> int
  (** Bit-size of a public key. *)

  val priv_bits : priv -> int
  (** Bit-size of a private key. *)

  val priv_of_primes : e:Z.t -> p:Z.t -> q:Z.t -> priv
  (** [priv_of_primes e p q] creates {{!priv}priv} from a minimal description:
      the public exponent and the two primes. *)

  val pub_of_priv : priv -> pub
  (** Extract the public component from a private key. *)

  val encrypt : key:pub  -> Cstruct.t -> Cstruct.t
  (** [encrypt key message] is the encrypted [message].
      @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
  (** [decrypt mask key ciphertext] is the decrypted [ciphertext], left-padded
      with [0x00] up to [key] size.
      @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

  val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv
  (** [generate g e bits] is a new {{!priv}priv}. [e] defaults to [2^16+1].
      @raise Invalid_argument if [e] is bad or [bits] is too small. *)

  (** {1 PKCS#1 padded modes} *)

  (** {b PKCS v1.5}-padded operations, as defined by {b PKCS #1 v1.5}.

      Keys must have a minimum of [11 + len(message)] bytes. *)
  module PKCS1 : sig

    module type S = sig
      (** RFC3477-compliant RSASSA-PKCS1-v1_5-SIGN and RSASSA-PKCS1-v1_5-VERIFY
          operating with PKCS1 (type 1)-padded signatures *)

      type t
      (** An initialized hash state that enables signing or verifying large
        messages that may not fit in memory through the use of [feed t chunk].
        Be aware that the [sign_t] and [verify_t] functions finalize the hash state, making it illegal to read out using [Hash.S.get], or to call the signing/verifying functions multiple times.
       *)

      val minimum_key_bits : int
      (** The minimum size of keys that can work with this signature type *)

      val init : unit -> t
      (** [init ()] initializes a new hash state. It is an alias of Hash.S.init. *)

      val feed : t -> Cstruct.t -> unit
      (** [feed t data] updates the internal state [t] with [data] *)

      val sign_cs : ?mask:mask -> key:priv -> digest:Cstruct.t -> Cstruct.t
      (** [sign_cs key digest] is the RSASSA-PKCS1-V1_5 signature on the [digest] signed by the [key].
          NOTE: [digest] will be used directly as the hash of the message you are signing, without verification, as part of the EMSA-PKCS1-V1_5-encoding. Care must be taken when using this function; you should probably use [sign_t] if at all possible.
          @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

      val sign_t : ?mask:mask -> key:priv -> t -> Cstruct.t
      (** [sign_t key t] is the RSASSA-PKCS1-V1_5 signature on [t] signed by the [key].
          NOTE: [t] will be in an illegal state after signing, and must not be used again.
          @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

      val sign : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
      (** [sign key msg] is the RSASSA-PKCS1-V1_5 signature on [msg] signed by the [key].
          @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

      val verify_cs : key:pub -> digest:Cstruct.t -> Cstruct.t -> bool
      (** [verify_cs key digest signature] verifies that [signature] is the RSASSA-PKCS1-V1_5 signature on the [digest].
          NOTE: [digest] will be used directly as the hash of the message you are verifying, without verification, as part of the EMSA-PKCS1-V1_5-encoding. Care must be taken when using this function; you should probably use [verify_t] if at all possible. *)

      val verify_t : key:pub -> t -> Cstruct.t -> bool
      (** [verify_t key t signature] verifies that [signature] is the RSASSA-PKCS1 V1_5 signature on the data hashed in [t], signed by [key].
          NOTE: [t] will be in an illegal state after verifying, and must not be used again. *)

      val verify : key:pub -> msg:Cstruct.t -> Cstruct.t -> bool
      (** [verify key msg signature] verifies that [signature] is the RSASSA-PKCS1 V1_5 signature on [msg], signed by [key]. *)

    end

    module Make : functor (H : Hash.S) ->
                  functor (Parameter : sig val asn_stub : Cstruct.t end) ->
                  S with type t = H.t
    module MD5  : S with type t = Hash.MD5.t
    module SHA1 : S with type t = Hash.SHA1.t
    module SHA224 : S with type t = Hash.SHA224.t
    module SHA256 : S with type t = Hash.SHA256.t
    module SHA384 : S with type t = Hash.SHA384.t
    module SHA512 : S with type t = Hash.SHA512.t

    val sig_encode : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
    (** [sig_encode mask key message] is almost the RSASSA-PKCS1-V1_5 signature by [key] on the digest passed as [message], with a caveat: This function is similar to PKCS1.S.sign_cs, but [sig_encode] does not prepend the ASN.1-DER-encoded hash algorithm structure to [message]. This can be used to implement the signing scheme used in older versions of SSL/TLS where the concatenation of two hashes are used instead.
        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

    val sig_decode : key:pub -> Cstruct.t -> Cstruct.t option
    (** [sig_decode key signature] is either [Some message] if the [signature]
        was produced with the given [key] as per {{!sig_decode}sig_decode}, or [None] *)

    val encrypt : ?g:Rng.g -> key:pub -> Cstruct.t -> Cstruct.t
    (** [encrypt g key message] is RSAES-PKCS1-V1_5-ENCRYPT-transformed [message] encrypted to [key].
        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

    val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
    (** [decrypt mask key ciphertext] is [Some message] if the [ciphertext] was
        produced by the corresponding {{!encrypt}encrypt} operation, or [None]
        otherwise. This implements RSAES-PKCS1-V1_5-DECRYPT. *)
  end

  (** {b OAEP}-padded encryption, as defined by {b PKCS #1 v2.1}.

      The same hash function is used for padding and MGF. MGF is {b MGF1} as
      defined in {b PKCS #1 2.1}.

      Keys must have a minimum of [2 + 2 * hlen + len(message)] bytes, where
      [hlen] is the hash length. *)
  module OAEP (H : Hash.S) : sig

    val encrypt : ?g:Rng.g -> ?label:Cstruct.t -> key:pub -> Cstruct.t -> Cstruct.t
    (** [encrypt ~g ~label ~key message] is {b OAEP}-padded and encrypted
        [message], using the optional [label].
        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

    val decrypt : ?mask:mask -> ?label:Cstruct.t -> key:priv -> Cstruct.t -> Cstruct.t option
    (** [decrypt ~mask ~label ~key ciphertext] is [Some message] if the
        [ciphertext] was produced by the corresponding {{!encrypt}encrypt}
        operation, or [None] otherwise. *)
  end

  (** {b PSS}-based signing, as defined by {b PKCS #1 v2.1}.

      The same hash function is used for padding, MGF and computing message
      digest. MGF is {b MGF1} as defined in {b PKCS #1 2.1}.

      Keys must have a minimum of [2 + hlen + slen] bytes, where [hlen] is the
      hash length and [slen] is the seed length. *)
  module PSS (H: Hash.S) : sig

    val sign : ?g:Rng.g -> ?slen:int -> key:priv -> Cstruct.t -> Cstruct.t
    (** [sign ~g ~slen ~key message] the {p PSS}-padded digest of [message],
        signed with the [key]. [slen] is the optional seed length and default to
        the size of the underlying hash function.
        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

    val verify : ?slen:int -> key:pub -> signature:Cstruct.t -> Cstruct.t -> bool
    (** [verify ~slen ~key ~signature message] checks whether [signature] is a
        valid {b PSS} signature of the [message] under the given [key]. *)
  end

  (**/**)
  val pub_of_sexp : Sexplib.Sexp.t -> pub
  val sexp_of_pub : pub -> Sexplib.Sexp.t

  val priv_of_sexp : Sexplib.Sexp.t -> priv
  val sexp_of_priv : priv -> Sexplib.Sexp.t
  (**/**)

end


(** {b DSA} digital signature algorithm. *)
module Dsa : sig

  (** {1 DSA signature algorithm} *)

  type priv = {
    p  : Z.t ; (** Modulus *)
    q  : Z.t ; (** Subgroup order *)
    gg : Z.t ; (** Group Generator *)
    x  : Z.t ; (** Private key proper *)
    y  : Z.t ; (** Public component *)
  }
  (** Private key. [p], [q] and [gg] comprise {i domain parameters}.

      {e [Sexplib] convertible}. *)

  type pub  = {
    p  : Z.t ;
    q  : Z.t ;
    gg : Z.t ;
    y  : Z.t ;
  }
  (** Public key, a subset of {{!priv}private key}.

      {e [Sexplib] convertible}. *)

  type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `Exactly of int * int ]
  (** Key size request. Three {e Fips} variants refer to FIPS-standardized
      L-values ([p] size) and imply the corresponding N ([q] size); The last
      variants specifies L and N directly. *)

  type mask = [ `No | `Yes | `Yes_with of Rng.g ]
  (** Masking (cryptographic blinding) option. *)

  val pub_of_priv : priv -> pub
  (** Extract the public component from a private key. *)

  val generate : ?g:Rng.g -> keysize -> priv
  (** [generate g size] is a fresh {{!priv}private} key. The domain parameters
      are derived using a modified FIPS.186-4 probabilistic process, but the
      derivation can not be validated. *)

  val sign : ?mask:mask -> ?k:Z.t -> key:priv -> Cstruct.t -> Cstruct.t * Cstruct.t
  (** [sign mask k fips key digest] is the signature, a pair of {!Cstruct.t}s
      representing [r] and [s] in big-endian.

      [digest] is the full digest of the actual message.

      [k], the random component, can either be provided, or is deterministically
      derived as per RFC6979, using SHA256.  *)

  val verify : key:pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool
  (** [verify fips key (r, s) digest] verifies that the pair [(r, s)] is the signature
      of [digest], the message digest, under the private counterpart to [key]. *)

  val massage : key:pub -> Cstruct.t -> Cstruct.t
  (** [massage key digest] is the numeric value of [digest] taken modulo [q] and
      represented in the leftmost [bits(q)] bits of the result.

      Both FIPS.186-4 and RFC6979 specify that only the leftmost [bits(q)] bits of
      [digest] are to be taken into account, but some implementations consider the
      entire [digest]. In cases where {{!sign}sign} and {{!verify}verify} seem
      incompatible with a given implementation (esp. if {{!sign}sign} produces
      signatures with the [s] component different from the other
      implementation's), it might help to pre-process [digest] using this
      function (e.g. [sign ~key (massage ~key:(pub_of_priv key) digest)]).  *)

  (** [K_gen] can be instantiated over a hashing module to obtain an RFC6979
      compliant [k]-generator for that hash. *)
  module K_gen (H : Hash.S) : sig

    val generate : key:priv -> Cstruct.t -> Z.t
    (** [generate key digest] deterministically takes the given private key and
        message digest to a [k] suitable for seeding the signing process. *)
  end

  (**/**)
  val pub_of_sexp : Sexplib.Sexp.t -> pub
  val sexp_of_pub : pub -> Sexplib.Sexp.t

  val priv_of_sexp : Sexplib.Sexp.t -> priv
  val sexp_of_priv : priv -> Sexplib.Sexp.t
  (**/**)

end


(** Diffie-Hellman, MODP version. *)
module Dh : sig

  (** {1 Diffie-Hellman key exchange} *)

  exception Invalid_public_key
  (** Raised if the public key is degenerate. Implies either badly malfunctioning
      DH on the other side, or an attack attempt. *)

  type group = {
    p  : Z.t ;        (** modulus *)
    gg : Z.t ;        (** generator *)
    q  : Z.t option ; (** subgroup order; potentially unknown *)
  }
  (** A DH group.

      {e [Sexplib] convertible}. *)

  type secret = private { x : Z.t }
  (** A private secret.

      {e [Sexplib] convertible.} *)

  val modulus_size : group -> int
  (** Bit size of the modulus. *)

  val key_of_secret : group -> s:Cstruct.t -> secret * Cstruct.t
  (** [key_of_secret group s] is the {!secret} and the corresponding public
      key which use [s] as the secret exponent.
      @raise Invalid_public_key if [s] is degenerate. *)

  val gen_key : ?g:Rng.g -> ?bits:int -> group -> secret * Cstruct.t
  (** Generate a random {!secret} and the corresponding public key.
      [bits] is the exact bit-size of {!secret} and defaults to a value
      dependent on the {!group}'s [p]. *)

  val shared : group -> secret -> Cstruct.t -> Cstruct.t option
  (** [shared group secret message] is [Some key], the shared key, given a
      group, a previously generated {!secret} and the other party's public
      message. It is [None] if [message] is degenerate. *)

  val gen_group : ?g:Rng.g -> int -> group
  (** [gen_group bits] generates a random {!group} with modulus size [bits].
      Uses a safe prime [p = 2q + 1] (with [q] prime) for the modulus and [2]
      for the generator, such that [2^q = 1 mod p].
      Runtime is on the order of minute for 1024 bits.

      @raise Invalid_argument if [bits] is ridiculously small.  *)

  (** A small catalog of standardized {!group}s. *)
  module Group : sig

    (** From RFC 2409: *)

    val oakley_1 : group
    val oakley_2 : group

    (** From RFC 3526: *)

    val oakley_5  : group
    val oakley_14 : group
    val oakley_15 : group
    val oakley_16 : group
    val oakley_17 : group
    val oakley_18 : group

    (** From RFC 5114: *)

    val rfc_5114_1 : group
    val rfc_5114_2 : group
    val rfc_5114_3 : group

    (** From draft-ietf-tls-negotiated-ff-dhe-08 *)

    val ffdhe2048 : group
    val ffdhe3072 : group
    val ffdhe4096 : group
    val ffdhe6144 : group
    val ffdhe8192 : group

  end

  (**/**)
  val group_of_sexp : Sexplib.Sexp.t -> group
  val sexp_of_group : group -> Sexplib.Sexp.t

  val secret_of_sexp : Sexplib.Sexp.t -> secret
  val sexp_of_secret : secret -> Sexplib.Sexp.t
  (**/**)

end
