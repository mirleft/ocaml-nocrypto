(** A lighweight crypto library. *)

module Base64 : sig
  val encode : Cstruct.t -> Cstruct.t
  val decode : Cstruct.t -> Cstruct.t
  val is_base64_char : char -> bool
end

module Uncommon : sig
(** A treasure-trove of random utilities.
 This is largely an internal API and prone to breakage. *)

  val cdiv : int -> int -> int
  val (&.) : ('b -> 'c) -> ('a -> 'b) -> 'a -> 'c
  val id   : 'a -> 'a

  module Cs : sig
  (** Addons to Cstruct. *)

    val empty : Cstruct.t
    val null : Cstruct.t -> bool
    val append : Cstruct.t -> Cstruct.t -> Cstruct.t
    val (<>) : Cstruct.t -> Cstruct.t -> Cstruct.t
    val concat : Cstruct.t list -> Cstruct.t
    val equal : ?mask:bool -> Cstruct.t -> Cstruct.t -> bool
    val clone : ?n:int -> Cstruct.t -> Cstruct.t
    val xor_into : Cstruct.t -> Cstruct.t -> int -> unit
    val xor : Cstruct.t -> Cstruct.t -> Cstruct.t
    val fill : Cstruct.t -> int -> unit
    val create_with : int -> int -> Cstruct.t

    val of_hex : string -> Cstruct.t

    val (lsl) : Cstruct.t -> int -> Cstruct.t
    val (lsr) : Cstruct.t -> int -> Cstruct.t
  end

  module Arr : sig
    val mem : 'a -> 'a array -> bool
  end
end

module Numeric : sig
  (** Numeric utilities. *)

  module type T = sig
    (** An augmented numeric type, consisting of basic common numeric ops,
        a range of converstions to and from variously-sized int types, and
        a few basic function for representing such numbers as {!Cstruct.t}.
    *)

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

  module Fc : sig
    type 'a t = (module T with type t = 'a)
    val int   : int   t
    val int32 : int32 t
    val int64 : int64 t
    val z     : Z.t   t
  end

  (* Misc elementary number theory functions. *)
  val pseudoprime : Z.t -> bool

end

module Hash : sig

  module type T = sig include Module_types.Hash end

  module MD5     : T
  module SHA1    : T
  module SHA224  : T
  module SHA256  : T
  module SHA384  : T
  module SHA512  : T
  module SHAd256 : sig include Module_types.Basic_hash end

  (* A set of simpler short-hands for common operations over varying hashes. *)

  type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ] with sexp

  val digest      : [< hash ] -> Cstruct.t -> Cstruct.t
  val mac         : [< hash ] -> key:Cstruct.t -> Cstruct.t -> Cstruct.t
  val digest_size : [< hash ] -> int
  val module_of   : [< hash ] -> (module T)

end

module Cipher_block : sig

  module T : sig
    (** Types of exported modules. *)

    module type Counter = sig val increment : Cstruct.t -> unit end

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

    module type ECB = sig

      type key
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val encrypt : key:key -> Cstruct.t -> Cstruct.t
      val decrypt : key:key -> Cstruct.t -> Cstruct.t
    end

    module type CBC = sig

      type key
      type result = { message : Cstruct.t ; iv : Cstruct.t }
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
      val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
    end

    module type CTR = sig

      type key
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val stream  : key:key -> ctr:Cstruct.t -> int -> Cstruct.t
      val encrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t
      val decrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t
    end

    module type GCM = sig
      type key
      type result = { message : Cstruct.t ; tag : Cstruct.t }
      val of_secret : Cstruct.t -> key

      val key_sizes  : int array
      val block_size : int
      val encrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
      val decrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
    end

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

  module Counters : sig
    module Inc_LE : T.Counter
    module Inc_BE : T.Counter
  end

  module AES : sig
    module Raw : T.Raw
    module ECB : T.ECB
    module CBC : T.CBC
    module CTR : functor (C : T.Counter) -> T.CTR
    module GCM : T.GCM
    module CCM : T.CCM
  end

  module DES : sig
    module Raw : T.Raw
    module ECB : T.ECB
    module CBC : T.CBC
    module CTR : functor (C : T.Counter) -> T.CTR
  end
end

module Cipher_stream : sig

  module type T = sig include Module_types.Stream_cipher end

  module ARC4 : T
end

module Fortuna : sig
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
  (** [reseed ~g bytes] updates [g] by mixing in [bytes] which should be
   unpredictable and ideally environmentally sourced. *)
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
end

module Hmac_drgb : sig
  module Make (H : Hash.T) : sig
    (** HMAC_DRBG: A NIST-specified RNG based on HMAC construction over the
        provided hash. *)

    type g

    val create : unit -> g
    val reseed : ?g:g -> Cstruct.t -> unit

    include Module_types.Random.Rng with type g := g
  end
end

module Rng : sig
(** A global instance of {!Fortuna}. *)

  open Module_types

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
end

module Rsa : sig
  (** RSA public-key cryptography.

  Keys are taken to be trusted material, and their properties are not checked.

  Messages are checked not to exceed the key size, and this is signalled via
  exceptions.

  Private-key operations are optionally protected through RSA blinding.
  *)

  (** Raised if the numeric magnitude of a message, with potential padding, is
  inappropriate for a given key, i.e. the message, when interpreted as big-endian
  encoding of a natural number, meets or exceeds the key's [n], or is 0. *)
  exception Invalid_message

  (** A public key *)
  type pub  = {
    e : Z.t ; (** Public exponent *)
    n : Z.t ; (** Modulus *)
  } with sexp

  (** A private key (two-prime version) *)
  type priv = {
    e  : Z.t ; (** Public exponent *)
    d  : Z.t ; (** Private exponent *)
    n  : Z.t ; (** Modulus *)
    p  : Z.t ; (** [p], one of two primes *)
    q  : Z.t ; (** [q], one of two primes *)
    dp : Z.t ; (** [d mod (p-1)] *)
    dq : Z.t ; (** [d mod (q-1)] *)
    q' : Z.t ; (** [q^(-1) mod p] *)
  } with sexp

  (** Masking (blinding) request. *)
  type mask = [
    | `No                (** Don't perform blinding. *)
    | `Yes               (** Use default {!Rng.g} for blinding. *)
    | `Yes_with of Rng.g (** Use the provided {!Rng.g} for blinding. *)
  ]

  (** Bit-size of a public key. *)
  val pub_bits : pub -> int

  (** Bit-size of a private key. *)
  val priv_bits : priv -> int

  (** [priv_of_primes e p q] creates {!priv} from a minimal description: the
  public exponent and the two primes. *)
  val priv_of_primes : e:Z.t -> p:Z.t -> q:Z.t -> priv

  (** Extract the public component from a private key. *)
  val pub_of_priv : priv -> pub

  (** [encrypt key message] is the encrypted [message].
    @raise Invalid_message (see {!Invalid_message}) *)
  val encrypt : key:pub  -> Cstruct.t -> Cstruct.t

  (** [decrypt mask key ciphertext] is the decrypted [ciphertext], left-padded
    with [0x00] up to [key] size.
    @raise Invalid_message (see above {!Invalid_message}) *)
  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t

  (** [generate g e bits] is a new {!priv}. [e] defaults to [2^16+1].
  @raise Invalid_argument if [e] is bad or [bits] is too small. *)
  val generate : ?g:Rng.g -> ?e:Z.t -> int -> priv


  (** Module providing operations with {b PKCS1} padding.

  The operations that take cleartext to ciphertext, {!sign} and {!encrypt},
  assume that the key has enough bits to encode the message and the padding, and
  raise exceptions otherwise. The operations that recover cleartext from
  ciphertext, {!verify} and {!decrypt}, return size and padding mismatches as
  [None].
  *)
  module PKCS1 : sig

    (** [sign mask key message] is the PKCS1-padded (type 1) signature of the
    [message].
    @raise Invalid_message (see above {!Invalid_message}) *)
    val sign : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t

    (** [verify key signature] is either the message that was PKCS1-padded and
    transformed with [key]'s private counterpart, or [None] if the padding is
    incorrect or the underlying {!Rsa.encrypt} would raise. *)
    val verify : key:pub -> Cstruct.t -> Cstruct.t option

    (** [encrypt g key message] is a PKCS1-padded (type 2) and encrypted
    [message].
    @raise Invalid_message (see above {!Invalid_message}) *)
    val encrypt : ?g:Rng.g -> key:pub -> Cstruct.t -> Cstruct.t

    (** [decrypt mask key ciphertext] is decrypted [ciphertext] stripped of PKCS1
    padding, or [None] if the padding is incorrect or the underlying
    {!Rsa.decrypt} would raise. *)
    val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
  end
end

module Dsa : sig
(** DSA digital signature algorithm. *)

  (** Private key. [p], [q] and [gg] comprise {i domain parameters}. *)
  type priv = {
    p  : Z.t ; (** Modulus *)
    q  : Z.t ; (** Subgroup order *)
    gg : Z.t ; (** Group Generator *)
    x  : Z.t ; (** Private key proper *)
    y  : Z.t ; (** Public component *)
  } with sexp

  (** Public key, a subset of {!priv}. *)
  type pub  = {
    p  : Z.t ;
    q  : Z.t ;
    gg : Z.t ;
    y  : Z.t ;
  } with sexp

  (** Key size request. Three {e Fips} variants refer to FIPS-standardized
      L-values ([p] size) and imply the corresponding N ([q] size); The last
      variants specifies L and N directly. *)
  type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `Exactly of int * int ]

  (** Masking request. *)
  type mask = [ `No | `Yes | `Yes_with of Rng.g ]

  (** Extract the public component from a private key. *)
  val pub_of_priv : priv -> pub

  (** [generate g size] is a fresh {!priv} key. The domain parameters are derived
      using a modified FIPS.186-4 probabilistic process, but the derivation can
      not be validated. *)
  val generate : ?g:Rng.g -> keysize -> priv

  (** [sign mask k fips key digest] is the signature, a pair of {!Cstruct.t}s
      representing [r] and [s] in big-endian.

      [digest] is the full digest of the actual message.

      [k], the random component, can either be provided, or is deterministically
      derived as per RFC6979, using SHA256.
  *)
  val sign : ?mask:mask -> ?k:Z.t -> key:priv -> Cstruct.t -> Cstruct.t * Cstruct.t

  (** [verify fips key (r, s) digest] verifies that the pair [(r, s)] is the signature
      of [digest], the message digest, under the private counterpart to [key]. *)
  val verify : key:pub -> Cstruct.t * Cstruct.t -> Cstruct.t -> bool

  (** [K_gen] can be instantiated over a hashing module to obtain an RFC6979
      compliant [k]-generator over that hash. *)
  module K_gen (H : Hash.T) : sig
    (** [generate key digest] deterministically takes the given private key and
        message digest to a [k] suitable for seeding the signing process. *)
    val generate : key:priv -> Cstruct.t -> Z.t
  end

  (** [massage key digest] is the numeric value of [digest] taken modulo [q] and
      represented in the leftmost [bits(q)] bits of the result.

      Both FIPS.186-4 and RFC6979 specify that only the leftmost [bits(q)] bits of
      [digest] are to be taken into account, but some implementations consider the
      entire [digest]. In cases where {!sign} and {!verify} seem incompatible with
      a given implementation (esp. if {!sign} produces signatures with the [s]
      component different from the other implementation's), it might help to
      pre-process [digest] using this function
      (e.g. [sign ~key (massage ~key:(pub_of_priv key) digest)]).
  *)
  val massage : key:pub -> Cstruct.t -> Cstruct.t
end

module Dh : sig
(** Diffie-Hellman, MODP version. *)

  (** Raised if the public key is degenerate. Implies either badly malfunctioning
      DH on the other side, or an attack attempt. *)
  exception Invalid_public_key

  (** A DH group. *)
  type group = {
    p  : Z.t ;        (** modulus *)
    gg : Z.t ;        (** generator *)
    q  : Z.t option ; (** subgroup order; potentially unknown *)
  } with sexp

  (** A private secret. *)
  type secret = { x : Z.t } with sexp

  (** Bit size of the modulus (not the subgroup order, which might not be known). *)
  val apparent_bit_size : group -> int

  (** [secret_of_cstruct group s] generates {! secret } and the public key, using
      [s] as secret.
      @raise Invalid_public_key if the secret is degenerate. *)
  val secret_of_cstruct : group -> s:Cstruct.t -> secret * Cstruct.t

  (** Generate a random {!secret} and the corresponding public message. *)
  val gen_secret : ?g:Rng.g -> group -> secret * Cstruct.t

  (** [shared group secret message] is the shared key, given a group, a previously
      generated {!secret} and the other party's public message.
      @raise Invalid_public_key if the public message is degenerate.  *)
  val shared : group -> secret -> Cstruct.t -> Cstruct.t

  (** [gen_group bits] generates a random {!group} with modulus size [bits].
      Uses a safe prime [p = 2q + 1] (with prime [q]) as modulus, and [2] or [q] as
      the generator.
      Subgroup order is strictly [q].
      Runtime is on the order of minute for 1024 bits.
      @raise Invalid_argument if [bits] is ridiculously small.
      *)
  val gen_group : ?g:Rng.g -> bits:int -> group

  (** A small catalog of standardized groups. *)
  module Group : sig

    val oakley_1   : group
    (** From RFC 2409. *)
    val oakley_2   : group
    (** From RFC 2409. *)

    val oakley_5   : group
    (** From RFC 3526. *)
    val oakley_14  : group
    (** From RFC 3526. *)
    val oakley_15  : group
    (** From RFC 3526. *)
    val oakley_16  : group
    (** From RFC 3526. *)
    val oakley_17  : group
    (** From RFC 3526. *)
    val oakley_18  : group
    (** From RFC 3526. *)

    val rfc_5114_1 : group
    (** From RFC 5114. *)
    val rfc_5114_2 : group
    (** From RFC 5114. *)
    val rfc_5114_3 : group
    (** From RFC 5114. *)

  end
end

(* module Module_types : module type of Module_types *)
