(** {b Nocrypto}: for when you're sick of crypto. *)

module Base64 : sig
  val encode : Cstruct.t -> Cstruct.t
  val decode : Cstruct.t -> Cstruct.t
  val is_base64_char : char -> bool
end


(** A treasure-trove of random utilities.

    This is largely an internal API and prone to breakage. *)
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
    val value : def:'a -> 'a option -> 'a
  end

  (** Addons to {!Cstruct}. *)
  module Cs : sig

    val empty : Cstruct.t
    val null  : Cstruct.t -> bool

    val (<+>) : Cstruct.t -> Cstruct.t -> Cstruct.t
    val concat : Cstruct.t list -> Cstruct.t

    val equal : ?mask:bool -> Cstruct.t -> Cstruct.t -> bool

    val xor_into : Cstruct.t -> Cstruct.t -> int -> unit
    val xor      : Cstruct.t -> Cstruct.t -> Cstruct.t

    val create_with : int -> int -> Cstruct.t

    val of_hex : string -> Cstruct.t

    val (lsl) : Cstruct.t -> int -> Cstruct.t
    val (lsr) : Cstruct.t -> int -> Cstruct.t
  end

  (** Addons to {!Array}. *)
  module Arr : sig
    val mem : 'a -> 'a array -> bool
  end
end


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
    val to_string : t -> string

    val bit_bound : t -> int

    val bits            : t -> int
    val of_cstruct_be   : ?bits:int -> Cstruct.t -> t
    val to_cstruct_be   : ?size:int -> t -> Cstruct.t
    val into_cstruct_be : t -> Cstruct.t -> unit

  end

  module Int   : S with type t = int
  module Int32 : S with type t = int32
  module Int64 : S with type t = int64
  module Z     : S with type t = Z.t

  (** Misc elementary number theory functions: *)

  val pseudoprime : Z.t -> bool
  (** Miller-Rabin with sane rounds parameter. *)

end


(** Hashes. *)
module Hash : sig

  (** Hash algorithm. *)
  module type S = sig

    type t (** Mutable hashing context. *)

    val digest_size : int (** Size of hashing results, in bytes. *)

    val init : unit -> t (** Create a new hashing context. *)
    val feed : t    -> Cstruct.t -> unit (** Update the context *)
    val get  : t    -> Cstruct.t (** Extract the digest; [t] becomes invalid. *)

    val digest  : Cstruct.t      -> Cstruct.t (** Digest in one go. *)
    val digestv : Cstruct.t list -> Cstruct.t (** Digest in one go. *)

    val hmac : key:Cstruct.t -> Cstruct.t -> Cstruct.t
    (** [hmac ~key bytes] is authentication code for [bytes] under the secret
        [key], generated using the standard HMAC construction over this hash
        algorithm. *)
  end

  module MD5     : S
  module SHA1    : S
  module SHA224  : S
  module SHA256  : S
  module SHA384  : S
  module SHA512  : S

  (** Simpler short-hands for common operations over varying hashes: *)

  type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ] with sexp

  val digest      : [< hash ] -> Cstruct.t -> Cstruct.t
  val mac         : [< hash ] -> key:Cstruct.t -> Cstruct.t -> Cstruct.t
  val digest_size : [< hash ] -> int
  val module_of   : [< hash ] -> (module S)

end


(** Block ciphers.  *)
module Cipher_block : sig

  (** Module types for various instantiations of block ciphers. *)
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
      type result = { message : Cstruct.t ; iv : Cstruct.t }
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
      val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
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

  (** {b AES}, plus a few modes of operation. *)
  module AES : sig
    val mode : [ `Generic | `AES_NI ]
(*     module Core : S.Core *)
    module ECB  : S.ECB
    module CBC  : S.CBC
    module CTR  : S.CTR
    module GCM  : S.GCM
    module CCM  : S.CCM
  end

  (** {b DES}, plus a few modes of operation. *)
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


(**
  General interface to randomness.

  It defines a general module type of generators, {!S.Generator}, a facility to
  convert such modules into generators that can be used uniformly, {!g}, and
  functions that operate on this generic representation.

  It contains a reference, {!generator}, to a global [g] instance.
  When not explicitly supplied a [g], random-generation functions use the
  contents of this reference. It starts with {!Fortuna}.

  It defines a module type of utilities for generating a particular numeric
  type, {!S.N}, contains instances of this module type for [int], [int32],
  [int64] and [Z.t], and functor to create them given a ground numeric type.

  It includes specialized operations for generating random primes.
*)
module Rng : sig


  type g
  (** A generator with its state. Changes when used. *)

  exception Unseeded_generator
  (** Thrown when using an uninitialized {!g}. *)


  (** Module signatures. *)
  module S : sig

    (** A single randomness-generating algorithm. *)
    module type Generator = sig

      type g
      (** State type for this generator. *)

      val block : int
      (** Internally, this generator's {!generate} always produces [k * block] bytes. *)

      val create : unit -> g
      (** Create a new, unseeded {!g}. *)

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
      (** [seeded ~g] is [true] iff operations won't throw {!Unseeded_generator}. *)

    end

    (** A suite of functions for generating numbers of a particular type. *)
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
          significant bits set, and interprets it as a {!t} in big-endidan. This
          yields a value in the interval [\[2^(n-1) + ... + 2^(n-msb), 2^n - 1\]].

          [msb] defaults to [0] which reduces [gen_bits k] to [gen 2^k]. *)
    end

  end


  module Generators : sig

    (** {b Fortuna}, a CSPRNG {{: https://www.schneier.com/fortuna.html} proposed}
        by Schneier. *)
    module Fortuna : S.Generator

    (** {b HMAC_DRBG}: A NIST-specified RNG based on HMAC construction over the
        provided hash. *)
    module Hmac_drgb : sig
      module Make (H : Hash.S) : S.Generator
    end

    module Null : S.Generator
    (** No-op generator returning exactly the bytes it was seeded with. *)

  end


  val create : ?strict:bool -> ?g:'a -> (module S.Generator with type g = 'a) -> g
  (** [create module] uses a module conforming to {!S.Generator} to instantiate
      the generic generator {!g}.

      [strict] puts the generator into a slighty more standards-conformant and
      slower mode. Useful if the outputs are to match published test-vectors. *)

  val generator : g ref
  (* The global {!g}. Functions in this module use this generator when not
     explicitly supplied one.

     [generator] defaults to {!Fortuna}. *)

  val generate : ?g:g -> int -> Cstruct.t
  (** Invoke {!S.Generator.generate} on [g] or {!generator}. *)

  val reseed : ?g:g -> Cstruct.t -> unit
  (** Invoke {!S.Generator.generate} on [g] or {!generator}. *)

  val accumulate : g option -> (source:int -> Cstruct.t -> unit) Uncommon.one
  (** Invoke {!S.Generator.accumulate} on [g] or {!generator}. *)

  val seeded : g option -> bool
  (** Invoke {!S.Generator.seeded} on [g] or {!generator}. *)

  val block : g option -> int
  (** {!S.Generator.block} size of [g] or {!generator}. *)


  module N_gen (N : Numeric.S) : S.N with type t = N.t
  (** Create a suite of generating functions over a numeric type. *)

  module Int   : S.N with type t = int
  module Int32 : S.N with type t = int32
  module Int64 : S.N with type t = int64
  module Z     : S.N with type t = Z.t


  val prime : ?g:g -> ?msb:int -> int -> Z.t
  (** [prime ~g ~msb bits] generates a prime smaller than [2^bits], with [msb]
      most significant bits set.

      [prime ~g ~msb:1 bits] (the default) yields a prime in the interval
      [\[2^(bits - 1), 2^bits - 1\]]. *)

  val safe_prime : ?g:g -> int -> Z.t * Z.t
  (** [safe_prime ~g bits] gives a prime pair [(g, p)] such that [p = 2g + 1]
      and [p] has [bits] significant bits. *)

end


(** {b RSA} public-key cryptography.

Keys are taken to be trusted material, and their properties are not checked.

Messages are checked not to exceed the key size, and this is signalled via
exceptions.

Private-key operations are optionally protected through RSA blinding.  *)
module Rsa : sig

  exception Insufficient_key
  (** Raised if the key is too small to transform the given message, i.e. if the
      numerical interpretation of the (potentially padded) message is not
      smaller than the modulus.
      It is additionally raised if the message is [0] and the mode does not
      involve padding. *)

  type pub  = {
    e : Z.t ; (** Public exponent *)
    n : Z.t ; (** Modulus *)
  } with sexp
  (** Public key *)

  type priv = {
    e  : Z.t ; (** Public exponent *)
    d  : Z.t ; (** Private exponent *)
    n  : Z.t ; (** Modulus *)
    p  : Z.t ; (** Prime factor [p] *)
    q  : Z.t ; (** Prime factor [q] *)
    dp : Z.t ; (** [d mod (p-1)] *)
    dq : Z.t ; (** [d mod (q-1)] *)
    q' : Z.t ; (** [q^(-1) mod p] *)
  } with sexp
  (** Private key (two-factor version) *)

  type mask = [
    | `No                (** Don't perform blinding. *)
    | `Yes               (** Use default {!Rng.g} for blinding. *)
    | `Yes_with of Rng.g (** Use the provided {!Rng.g} for blinding. *)
  ]
  (** Masking (blinding) request. *)

  val pub_bits : pub -> int
  (** Bit-size of a public key. *)

  val priv_bits : priv -> int
  (** Bit-size of a private key. *)

  val priv_of_primes : e:Z.t -> p:Z.t -> q:Z.t -> priv
  (** [priv_of_primes e p q] creates {!priv} from a minimal description: the
      public exponent and the two primes. *)

  val pub_of_priv : priv -> pub
  (** Extract the public component from a private key. *)

  val encrypt : key:pub  -> Cstruct.t -> Cstruct.t
  (** [encrypt key message] is the encrypted [message].
      @raise Insufficient_key (see {!Insufficient_key}) *)

  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
  (** [decrypt mask key ciphertext] is the decrypted [ciphertext], left-padded
      with [0x00] up to [key] size.
      @raise Insufficient_key (see {!Insufficient_key}) *)

  val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv
  (** [generate g e bits] is a new {!priv}. [e] defaults to [2^16+1].
      @raise Invalid_argument if [e] is bad or [bits] is too small. *)


  (** {b PKCS v1.5}-padded operations, as defined by {b PKCS #1 v1.5}.

      Keys must have a minimum of [11 + len(message)] bytes. *)
  module PKCS1 : sig

    val sign : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
    (** [sign mask key message] is the PKCS1-padded (type 1) [message] signed by
        the [key]. Note that this operation performs only the padding and RSA
        transformation steps of the PKCS 1.5 signature.
        @raise Insufficient_key (see {!Insufficient_key}) *)

    val verify : key:pub -> Cstruct.t -> Cstruct.t option
    (** [verify key signature] is either [Some message] if the [signature] was
        produced with the given [key] as per {!sign}, or [None] *)

    val encrypt : ?g:Rng.g -> key:pub -> Cstruct.t -> Cstruct.t
    (** [encrypt g key message] is a PKCS1-padded (type 2) and encrypted
        [message].
        @raise Insufficient_key (see {!Insufficient_key}) *)

    val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
    (** [decrypt mask key ciphertext] is [Some message] if the [ciphertext] was
        produced by the corresponding {!encrypt} operation, or [None] otherwise. *)
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
        @raise Insufficient_key (see {!Insufficient_key}) *)

    val decrypt : ?mask:mask -> ?label:Cstruct.t -> key:priv -> Cstruct.t -> Cstruct.t option
    (** [decrypt ~mask ~label ~key ciphertext] is [Some message] if the
        [ciphertext] was produced by the corresponding {!encrypt} operation,
        or [None] otherwise. *)
  end

  (** {b PSS}-passed signing, as defined by {b PKCS #1 v2.1}.

      The same hash function is used for padding, MGF and computing message
      digest. MGF is {b MGF1} as defined in {b PKCS #1 2.1}.

      Keys must have a minimum of [2 + hlen + slen] bytes, where [hlen] is the
      hash length and [slen] is the seed length. *)
  module PSS (H: Hash.S) : sig

    val sign : ?g:Rng.g -> ?slen:int -> key:priv -> Cstruct.t -> Cstruct.t
    (** [sign ~g ~slen ~key message] the {p PSS}-padded digest of [message],
        signed with the [key]. [slen] is the optional seed length and default to
        the size of the underlying hash function.
        @raise Insufficient_key (see {!Insufficient_key}) *)

    val verify : ?slen:int -> key:pub -> signature:Cstruct.t -> Cstruct.t -> bool
    (** [verify ~slen ~key ~signature message] checks whether [signature] is a
        valid {b PSS} signature of the [message] under the given [key]. *)
  end

end


(** {b DSA} digital signature algorithm. *)
module Dsa : sig

  type priv = {
    p  : Z.t ; (** Modulus *)
    q  : Z.t ; (** Subgroup order *)
    gg : Z.t ; (** Group Generator *)
    x  : Z.t ; (** Private key proper *)
    y  : Z.t ; (** Public component *)
  } with sexp
  (** Private key. [p], [q] and [gg] comprise {i domain parameters}. *)

  type pub  = {
    p  : Z.t ;
    q  : Z.t ;
    gg : Z.t ;
    y  : Z.t ;
  } with sexp
  (** Public key, a subset of {!priv}. *)

  type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `Exactly of int * int ]
  (** Key size request. Three {e Fips} variants refer to FIPS-standardized
      L-values ([p] size) and imply the corresponding N ([q] size); The last
      variants specifies L and N directly. *)

  type mask = [ `No | `Yes | `Yes_with of Rng.g ]
  (** Masking request. *)

  val pub_of_priv : priv -> pub
  (** Extract the public component from a private key. *)

  val generate : ?g:Rng.g -> keysize -> priv
  (** [generate g size] is a fresh {!priv} key. The domain parameters are derived
      using a modified FIPS.186-4 probabilistic process, but the derivation can
      not be validated. *)

  val sign : ?mask:mask -> ?k:Z.t -> key:priv -> Cstruct.t -> Cstruct.t * Cstruct.t
  (** [sign mask k fips key digest] is the signature, a pair of {!Cstruct.t}s
      representing [r] and [s] in big-endian.

      [digest] is the full digest of the actual message.

      [k], the random component, can either be provided, or is deterministically
      derived as per RFC6979, using SHA256.  *)

  val verify : key:pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool
  (** [verify fips key (r, s) digest] verifies that the pair [(r, s)] is the signature
      of [digest], the message digest, under the private counterpart to [key]. *)

  module K_gen (H : Hash.S) : sig
  (** [K_gen] can be instantiated over a hashing module to obtain an RFC6979
      compliant [k]-generator over that hash. *)

    val generate : key:priv -> Cstruct.t -> Z.t
    (** [generate key digest] deterministically takes the given private key and
        message digest to a [k] suitable for seeding the signing process. *)
  end

  val massage : key:pub -> Cstruct.t -> Cstruct.t
  (** [massage key digest] is the numeric value of [digest] taken modulo [q] and
      represented in the leftmost [bits(q)] bits of the result.

      Both FIPS.186-4 and RFC6979 specify that only the leftmost [bits(q)] bits of
      [digest] are to be taken into account, but some implementations consider the
      entire [digest]. In cases where {!sign} and {!verify} seem incompatible with
      a given implementation (esp. if {!sign} produces signatures with the [s]
      component different from the other implementation's), it might help to
      pre-process [digest] using this function
      (e.g. [sign ~key (massage ~key:(pub_of_priv key) digest)]).  *)
end


(** Diffie-Hellman, MODP version. *)
module Dh : sig

  exception Invalid_public_key
  (** Raised if the public key is degenerate. Implies either badly malfunctioning
      DH on the other side, or an attack attempt. *)

  type group = {
    p  : Z.t ;        (** modulus *)
    gg : Z.t ;        (** generator *)
    q  : Z.t option ; (** subgroup order; potentially unknown *)
  } with sexp
  (** A DH group. *)

  type secret = { x : Z.t } with sexp
  (** A private secret. *)

  val apparent_bit_size : group -> int
  (** Bit size of the modulus (not the subgroup order, which might not be known). *)

  val secret_of_cstruct : group -> s:Cstruct.t -> secret * Cstruct.t
  (** [secret_of_cstruct group s] generates {! secret } and the public key, using
      [s] as secret.
      @raise Invalid_public_key if the secret is degenerate. *)

  val gen_secret : ?g:Rng.g -> ?bits:int -> group -> secret * Cstruct.t
  (** Generate a random {!secret} and the corresponding public message.
      [bits] is the exact bit-size of {!secret} and defaults to a value
      dependent on the {!group}'s [p]. *)

  val shared : group -> secret -> Cstruct.t -> Cstruct.t
  (** [shared group secret message] is the shared key, given a group, a previously
      generated {!secret} and the other party's public message.
      @raise Invalid_public_key if the public message is degenerate.  *)

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
end
