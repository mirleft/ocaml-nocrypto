(** {b Nocrypto}: for when you're sick of crypto. *)

module Base64 : sig
  val encode : Cstruct.t -> Cstruct.t
  val decode : Cstruct.t -> Cstruct.t
  val is_base64_char : char -> bool
end


(** A treasure-trove of random utilities.
    This is largely an internal API and prone to breakage. *)
module Uncommon : sig

  val cdiv : int -> int -> int

  val (&.) : ('b -> 'c) -> ('a -> 'b) -> 'a -> 'c
  val id   : 'a -> 'a

  (** Addons to {!Cstruct}. *)
  module Cs : sig

    val empty : Cstruct.t
    val null  : Cstruct.t -> bool

    val (<+>) : Cstruct.t -> Cstruct.t -> Cstruct.t
    val concat : Cstruct.t list -> Cstruct.t

    val equal : ?mask:bool -> Cstruct.t -> Cstruct.t -> bool

    val xor_into : Cstruct.t -> Cstruct.t -> int -> unit
    val xor      : Cstruct.t -> Cstruct.t -> Cstruct.t

    val fill : Cstruct.t -> int -> unit
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
  module type T = sig

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

  module Int   : T with type t = int
  module Int32 : T with type t = int32
  module Int64 : T with type t = int64
  module Z     : T with type t = Z.t

  (** Misc elementary number theory functions: *)

  val pseudoprime : Z.t -> bool
  (** Miller-Rabin with sane rounds parameter. *)

end


(** Hashes. *)
module Hash : sig

  (** Hash algorithm. *)
  module type T = sig

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

  module MD5     : T
  module SHA1    : T
  module SHA224  : T
  module SHA256  : T
  module SHA384  : T
  module SHA512  : T

  (** Simpler short-hands for common operations over varying hashes: *)

  type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ] with sexp

  val digest      : [< hash ] -> Cstruct.t -> Cstruct.t
  val mac         : [< hash ] -> key:Cstruct.t -> Cstruct.t -> Cstruct.t
  val digest_size : [< hash ] -> int
  val module_of   : [< hash ] -> (module T)

end


(** Block ciphers.  *)
module Cipher_block : sig

  (** Module types for various instantiations of block ciphers. *)
  module T : sig

    (** Counter type for CTR. *)
    module type Counter = sig val increment : Cstruct.t -> unit end

    (** Raw block cipher in all its glory. *)
    module type Raw = sig

      type ekey
      type dkey

      val e_of_secret : Cstruct.t -> ekey
      val d_of_secret : Cstruct.t -> dkey

      val key_sizes  : int array
      val block_size : int
      val encrypt_block : key:ekey -> Cstruct.t -> Cstruct.t -> unit
      val decrypt_block : key:dkey -> Cstruct.t -> Cstruct.t -> unit
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
      val stream  : key:key -> ctr:Cstruct.t -> int -> Cstruct.t
      val encrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t
      val decrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t
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

  (** {!T.Counter}s for easy {!T.CTR} instantiation. *)
  module Counters : sig
    module Inc_LE : T.Counter
    (** Increment-by-one, little endian. Works on [8*n]-long vectors. *)
    module Inc_BE : T.Counter
    (** Increment-by-one, big endian. Works on [8*n]-long vectors. *)
  end

  (** {b AES}, plus a few modes of operation. *)
  module AES : sig
    module Raw : T.Raw
    module ECB : T.ECB
    module CBC : T.CBC
    module CTR : functor (C : T.Counter) -> T.CTR
    module GCM : T.GCM
    module CCM : T.CCM
  end

  (** {b DES}, plus a few modes of operation. *)
  module DES : sig
    module Raw : T.Raw
    module ECB : T.ECB
    module CBC : T.CBC
    module CTR : functor (C : T.Counter) -> T.CTR
  end
end


(** Streaming ciphers. *)
module Cipher_stream : sig

  (** General stream cipher type. *)
  module type T = sig
    type key
    type result = { message : Cstruct.t ; key : key }
    val of_secret : Cstruct.t -> key
    val encrypt : key:key -> Cstruct.t -> result
    val decrypt : key:key -> Cstruct.t -> result
  end

  (** {e Alleged Rivest Cipher 4}. *)
  module ARC4 : T
end


(** Implementation of {{: https://www.schneier.com/fortuna.html} Fortuna} CSPRNG. *)
module Fortuna : sig

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
  (** [reseed ~g bytes] updates [g] by mixing in [bytes] which should be
   unpredictable and ideally environmentally sourced. *)
  val reseedv  : g:g -> Cstruct.t list -> unit
  (** [reseedv ~g list] is like [reseed] with a concatenation of [list], but faster. *)
  val generate : g:g -> int -> Cstruct.t
  (** [generate ~g n] extracts [n] bytes of random stream from [g]. *)

  (** Accumulator pools, collecting entropy and periodically reseeding the
    attached {!g}.

    Reseeding is performed on the first {!generate} following a non-empty
    sequence of calls to {!add}.

    Each accumulator instance contains 32 entropy pools, which are taken into
    account with exponentially decreasing frequency and are meant to be fed
    round-robin.  *)
  module Accumulator : sig

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
      that. [pool]s should be rotated roughly round-robin.  *)
    val add_rr : acc:t -> (source:int -> Cstruct.t -> unit)
    (** [add_rr ~acc] is [fun], where each successive call to [fun ~source bytes]
    performs [add] with the next pool in [acc], in a round-robin fashion. *)

  end
end


(** HMAC_DRBG: A NIST-specified RNG based on HMAC construction over the
    provided hash. *)
module Hmac_drgb : sig

  module Make (H : Hash.T) : sig
    type g
    val block_size : int
    val create : unit -> g
    val reseed : ?g:g -> Cstruct.t -> unit
    val generate : ?g:g -> int -> Cstruct.t
  end
end


(** The global RNG. Instantiates {!Fortuna}. *)
module Rng : sig

  (** Module types. *)
  module T : sig

    (** The core random generator signature. *)
    module type Rng = sig

      type g
      (** State type for this generator. *)
      val block_size : int
      (** Internally, this generator's {!generate} always produces [k * block_size] bytes. *)
      val generate : ?g:g -> int -> Cstruct.t
      (** [generate ~g n] produces [n] random bytes, using either the given or a
          default {!g}. *)
    end

    (** Typed random number extraction: {!Rng} for a type [t]. *)
    module type N = sig

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

    (** RNG with full suite of typed numeric extractions. *)
    module type Rng_numeric = sig

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

      val strict : bool -> unit
    end
  end

  (** Produces the numeric extraction suite over a {!T.Rng}. *)
  module Numeric_of :
    functor (Rng : T.Rng) -> T.Rng_numeric with type g = Rng.g


  type g = Fortuna.g

  include T.Rng         with type g := g (** Base RNG generation. *)
  include T.Rng_numeric with type g := g (** Numeric RNG generation. *)

  val reseed  : Cstruct.t      -> unit
  val reseedv : Cstruct.t list -> unit
  val seeded  : unit           -> bool
  val set_gen : g:g            -> unit

  module Accumulator : sig
    val add    : source:int -> pool:int -> Cstruct.t -> unit
    val add_rr : source:int -> Cstruct.t -> unit
  end
end


(** {b RSA} public-key cryptography.

Keys are taken to be trusted material, and their properties are not checked.

Messages are checked not to exceed the key size, and this is signalled via
exceptions.

Private-key operations are optionally protected through RSA blinding.  *)
module Rsa : sig

  exception Invalid_message
  (** Raised if the numeric magnitude of a message, with potential padding, is
      inappropriate for a given key, i.e. the message, when interpreted as
      big-endian encoding of a natural number, meets or exceeds the key's [n],
      or is 0. *)

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
      @raise Invalid_message (see {!Invalid_message}) *)

  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
  (** [decrypt mask key ciphertext] is the decrypted [ciphertext], left-padded
      with [0x00] up to [key] size.
      @raise Invalid_message (see {!Invalid_message}) *)

  val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv
  (** [generate g e bits] is a new {!priv}. [e] defaults to [2^16+1].
      @raise Invalid_argument if [e] is bad or [bits] is too small. *)


  (** Module providing operations with {b PKCS1} padding.

      The operations that take cleartext to ciphertext, {!sign} and {!encrypt},
      assume that the key has enough bits to encode the message and the padding,
      and raise exceptions otherwise. The operations that recover cleartext
      from ciphertext, {!verify} and {!decrypt}, return size and padding
      mismatches as [None]. *)
  module PKCS1 : sig

    val sign : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
    (** [sign mask key message] is the PKCS1-padded (type 1) signature of the
        [message].
        @raise Invalid_message (see {!Invalid_message}) *)

    val verify : key:pub -> Cstruct.t -> Cstruct.t option
    (** [verify key signature] is either the message that was PKCS1-padded and
        transformed with [key]'s private counterpart, or [None] if the padding
        is incorrect or the underlying {!Rsa.encrypt} would raise. *)

    val encrypt : ?g:Rng.g -> key:pub -> Cstruct.t -> Cstruct.t
    (** [encrypt g key message] is a PKCS1-padded (type 2) and encrypted
        [message].
        @raise Invalid_message (see {!Invalid_message}) *)

    val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
    (** [decrypt mask key ciphertext] is decrypted [ciphertext] stripped of
        PKCS1 padding, or [None] if the padding is incorrect or the underlying
        {!Rsa.decrypt} would raise. *)
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

  module K_gen (H : Hash.T) : sig
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

  val gen_secret : ?g:Rng.g -> group -> secret * Cstruct.t
  (** Generate a random {!secret} and the corresponding public message. *)

  val shared : group -> secret -> Cstruct.t -> Cstruct.t
  (** [shared group secret message] is the shared key, given a group, a previously
      generated {!secret} and the other party's public message.
      @raise Invalid_public_key if the public message is degenerate.  *)

  val gen_group : ?g:Rng.g -> bits:int -> group
  (** [gen_group bits] generates a random {!group} with modulus size [bits].
      Uses a safe prime [p = 2q + 1] (with prime [q]) as modulus, and [2] or [q] as
      the generator.
      Subgroup order is strictly [q].
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
  end
end
