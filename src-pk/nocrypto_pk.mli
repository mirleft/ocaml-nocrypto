open Nocrypto_rng

(** {1 Public-key cryptography} *)

(** {b RSA} public-key cryptography.

Keys are taken to be trusted material, and their properties are not checked.

Messages are checked not to exceed the key size, and this is signalled via
exceptions.

Private-key operations are optionally protected through RSA blinding. *)
module Rsa : sig

  type bits = int

  (** {1 Keys}

      {b Warning} The behavior of functions in this module is undefined if the
      key material is not numerically well-formed. It is the responsibility of
      the client to ensure the trustworthiness of keys.

      The two anchoring points provided are {{!generate}[generate]} and
      {{!well_formed}[well_formed]}. *)

  exception Insufficient_key
  (** Raised if the key is too small to transform the given message, i.e. if the
      numerical interpretation of the (potentially padded) message is not
      smaller than the modulus. *)

  type pub  = {
    e : Z.t ; (** Public exponent *)
    n : Z.t ; (** Modulus *)
  }
  (** The public portion of the key. *)

  type priv = {
    e  : Z.t ; (** Public exponent *)
    d  : Z.t ; (** Private exponent *)
    n  : Z.t ; (** Modulus ([p q])*)
    p  : Z.t ; (** Prime factor [p] *)
    q  : Z.t ; (** Prime factor [q] *)
    dp : Z.t ; (** [d mod (p-1)] *)
    dq : Z.t ; (** [d mod (q-1)] *)
    q' : Z.t ; (** [q^(-1) mod p] *)
  }
  (** Full private key (two-factor version).

      {b Note} The key layout assumes that [p > q], which affects the quantity
      [q'] (sometimes called [u]), and the computation of the private transform.
      Some systems assume otherwise. When using keys produced by a system that
      computes [u = p^(-1) mod q], either exchange [p] with [q] and [dp] with
      [dq], or re-generate the full private key using
      {{!priv_of_primes}[priv_of_primes]}. *)

  val pub_bits : pub -> bits
  (** Bit-size of a public key. *)

  val priv_bits : priv -> bits
  (** Bit-size of a private key. *)

  val priv_of_primes : e:Z.t -> p:Z.t -> q:Z.t -> priv
  (** [priv_of_primes ~e ~p ~q] is the {{!priv}private key} derived from the
      minimal description [(e, p, q)].

      The triple is not checked for well-formedness.

      [p] is assumed to be the smaller factor. While the key will function
      correctly in either case, derived quantities will be different. See
      {{!priv} private keys}. *)

  val priv_of_exp : ?g:Rng.g -> ?attempts:int -> e:Z.t -> d:Z.t -> Z.t -> priv
  (** [priv_of_exp ?g ?attempts ~e ~d n] is the unique {{!priv}private key}
      characterized by the public ([e]) and private ([d]) exponents, and modulus
      [n]. This operation uses a probabilistic process that can fail to recover
      the key.

      [~attempts] is the number of trials. For triplets that form an RSA key,
      the probability of failure is at most [2^(-attempts)]. [attempts] defaults
      to an unspecified number that yields a very high probability of recovering
      valid keys.

      @raise Invalid_argument when [(e, d, n)] certainly do not form an RSA key.
      This includes violating [2 < e < n], [2 < d < n] or [2 < n].

      @raise Failure when the key has not been recovered after the given number
      of attempts. *)

  val pub_of_priv : priv -> pub
  (** Extract the public component from a private key. *)

  val well_formed : e:Z.t -> p:Z.t -> q:Z.t -> bool
  (** [well_formed ~e ~p ~q] indicates whether the triplet [(e, p, q)] can be
      used as an RSA key.

      It can, if:
      {ul
      {- [3 <= e];}
      {- [p != q];}
      {- [e], [p] and [q] are all primes; and}
      {- [e] is not a divisor of either [p - 1] or [q - 1].}}

      These are sufficient conditions to ensure that the behavior of other
      operations in this module is defined.

      This will not help with maliciously crafted keys that are simply
      numerically well-formed, however. Carefully consider which sources of keys
      to trust. *)

  (** {1 The RSA transformation} *)

  type mask = [ `No | `Yes | `Yes_with of Rng.g ]
  (** Masking (cryptographic blinding) mode for the RSA transform with the
      private key. Masking does not change the result, but it does change the
      timing profile of the operation.

      {ul
      {- [`No] disables masking. It is slightly faster but it {b exposes the
         private key to timing-based attacks}.}
      {- [`Yes] uses random masking with the global RNG instance. This is
         the sane option.}
      {- [`Yes_with g] uses random masking with the generator [g].}} *)

  val encrypt : key:pub  -> Cstruct.t -> Cstruct.t
  (** [encrypt key message] is the encrypted [message].

      @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key})

      @raise Invalid_argument if [message] is [0x00] or [0x01]. *)

  val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
  (** [decrypt ~mask key ciphertext] is the decrypted [ciphertext], left-padded
      with [0x00] up to [key] size.

      [~mask] defaults to [`Yes].

      @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

  (** {1 Key generation} *)

  val generate : ?g:Rng.g -> ?e:Z.t -> bits -> priv
  (** [generate g e bits] is a new {{!priv}private key}. The new key is
      guaranteed to be {{!well_formed}well formed}.

      [e] defaults to [2^16+1].

      {b Note} This process might diverge if there are no keys for the given
      bit size. This can happen when [bits] is extremely small.

      @raise Invalid_argument if [e] is not prime [3 <= e < 2^bits]. *)


  (** {1 PKCS#1 padded modes} *)

  (** {b PKCS v1.5} operations, as defined by {b PKCS #1 v1.5}.

      For the operations that only add the raw padding, the key size must be at
      least 11 bytes larger than the message. For full {{!sign}signing}, the
      minimal key size varies according to the hash algorithm. In this case, the
      key size is [priv_bits key / 8], rounded up. *)
  module PKCS1 : sig

    val encrypt : ?g:Rng.g -> key:pub -> Cstruct.t -> Cstruct.t
    (** [encrypt g key message] is a PKCS1-padded (type 2) and encrypted
        [message].

        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

    val decrypt : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t option
    (** [decrypt mask key ciphertext] is [Some message] if the [ciphertext] was
        produced by the corresponding {{!encrypt}encrypt} operation, or [None]
        otherwise. *)

    val sig_encode : ?mask:mask -> key:priv -> Cstruct.t -> Cstruct.t
    (** [sig_encode ?mask ~key message] is the PKCS1-padded (type 1) [message]
        signed by the [key].

        {b Note} This operation performs only the padding and RSA transformation
        steps of the PKCS 1.5 signature. The full signature is implemented by
        {{!sign}[sign]}.

        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key}) *)

    val sig_decode : key:pub -> Cstruct.t -> Cstruct.t option
    (** [sig_decode key signature] is [Some message] when the [signature]
        was produced with the given [key] as per {{!sig_encode}sig_encode}, or
        [None] *)

    open Nocrypto_hash

    val min_key : hash -> bits
    (** [min_key hash] is the minimum key size required by {{!sign}[sign]}. *)

    val sign : ?mask:mask -> hash:hash -> key:priv -> Cstruct.t or_digest -> Cstruct.t
    (** [sign ?mask ~hash ~key message] is the PKCS 1.5 signature of
        [message], signed by the [key], using the hash function [hash]. This is
        the full signature, with the ASN-encoded message digest as the payload.

        [message] is either the actual message, or its digest.

        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key})

        @raise Invalid_argument if message is a [`Digest] of the wrong size.  *)

    val verify : hashp:(hash -> bool) -> key:pub -> signature:Cstruct.t -> Cstruct.t or_digest -> bool
    (** [verify ~hashp ~key ~signature message] checks that [signature] is the
        PKCS 1.5 signature of the [message] under the given [key].

        [message] is either the actual message, or its digest.

        [hashp] determines the allowed hash algorithms. Whenever [hashp] is
        [false], [verify] is also [false].

        @raise Invalid_argument if message is a [`Digest] of the wrong size.  *)
  end

  (** {b OAEP}-padded encryption, as defined by {b PKCS #1 v2.1}.

      The same hash function is used for padding and MGF. MGF is {b MGF1} as
      defined in {b PKCS #1 2.1}.

      Keys must have a minimum of [2 + 2 * hlen + len(message)] bytes, where
      [hlen] is the hash length. *)
  module OAEP (H : Nocrypto_hash.S) : sig

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
  module PSS (H: Nocrypto_hash.S) : sig

    open Nocrypto_hash

    val sign : ?g:Rng.g -> ?mask:mask -> ?slen:int -> key:priv -> Cstruct.t or_digest -> Cstruct.t
    (** [sign ~g ~mask ~slen ~key message] the {p PSS}-padded digest of
        [message], signed with the [key].

        [slen] is the optional seed length and defaults to the size of the
        underlying hash function.

        [message] is either the actual message, or its digest.

        @raise Insufficient_key (see {{!Insufficient_key}Insufficient_key})

        @raise Invalid_argument if message is a [`Digest] of the wrong size.  *)

    val verify : ?slen:int -> key:pub -> signature:Cstruct.t -> Cstruct.t or_digest -> bool
    (** [verify ~slen ~key ~signature message] checks whether [signature] is a
        valid {b PSS} signature of the [message] under the given [key].

        [message] is either the actual message, or its digest.

        @raise Invalid_argument if message is a [`Digest] of the wrong size. *)
  end
end


(** {b DSA} digital signature algorithm. *)
module Dsa : sig

  type bits = int

  (** {1 DSA signature algorithm} *)

  type priv = {
    p  : Z.t ; (** Modulus *)
    q  : Z.t ; (** Subgroup order *)
    gg : Z.t ; (** Group Generator *)
    x  : Z.t ; (** Private key proper *)
    y  : Z.t ; (** Public component *)
  }
  (** Private key. [p], [q] and [gg] comprise {i domain parameters}. *)

  type pub  = {
    p  : Z.t ;
    q  : Z.t ;
    gg : Z.t ;
    y  : Z.t ;
  }
  (** Public key, a subset of {{!priv}private key}. *)

  type keysize = [ `Fips1024 | `Fips2048 | `Fips3072 | `Exactly of bits * bits ]
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
      derivation can not be validated.

      {b Note} The process might diverge if it is impossible to find parameters
      with the given bit sizes. This happens when [n] gets too big for [l], if
      the [size] was given as [`Exactly (l, n)].

      @raise Invalid_argument if [size] is (`Exactly (l, n)), and either [l] or
      [n] is ridiculously small. *)

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
  module K_gen (H : Nocrypto_hash.S) : sig

    val generate : key:priv -> Cstruct.t -> Z.t
    (** [generate key digest] deterministically takes the given private key and
        message digest to a [k] suitable for seeding the signing process. *)
  end
end


(** Diffie-Hellman, MODP version. *)
module Dh : sig

  type bits = int

  (** {1 Diffie-Hellman key exchange} *)

  exception Invalid_public_key
  (** Raised if the public key is degenerate. Implies either badly malfunctioning
      DH on the other side, or an attack attempt. *)

  type group = {
    p  : Z.t ;        (** modulus *)
    gg : Z.t ;        (** generator *)
    q  : Z.t option ; (** subgroup order; potentially unknown *)
  }
  (** A DH group. *)

  type secret = private { x : Z.t }
  (** A private secret. *)

  val modulus_size : group -> bits
  (** Bit size of the modulus. *)

  val key_of_secret : group -> s:Cstruct.t -> secret * Cstruct.t
  (** [key_of_secret group s] is the {!secret} and the corresponding public
      key which use [s] as the secret exponent.

      @raise Invalid_public_key if [s] is degenerate. *)

  val gen_key : ?g:Rng.g -> ?bits:bits -> group -> secret * Cstruct.t
  (** Generate a random {!secret} and the corresponding public key.
      [bits] is the exact bit-size of {!secret} and defaults to a value
      dependent on the {!group}'s [p].

      {b Note} The process might diverge when [bits] is extremely small. *)

  val shared : group -> secret -> Cstruct.t -> Cstruct.t option
  (** [shared group secret message] is [Some key], the shared key, given a
      group, a previously generated {!secret} and the other party's public
      message. It is [None] if [message] is degenerate. *)

  val gen_group : ?g:Rng.g -> bits -> group
  (** [gen_group bits] generates a random {!group} with modulus size [bits].
      Uses a safe prime [p = 2q + 1] (with [q] prime) for the modulus and [2]
      for the generator, such that [2^q = 1 mod p].
      Runtime is on the order of minute for 1024 bits.

      {b Note} The process might diverge if there are no suitable groups. This
      happens with extremely small [bits] values. *)

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
