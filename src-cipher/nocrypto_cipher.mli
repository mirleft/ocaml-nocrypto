
(** {1 Symmetric-key cryptography} *)

(** Block ciphers.

    Each algorithm, and each mode of operation, is contained in its own separate
    module. *)
module Cipher_block : sig

  (** Module types for various block cipher modes of operation. *)
  module S : sig

    (** Raw block cipher in all its glory.

        Make absolutely sure to check the arguments. Behavior is unspecified on
        invalid inputs. *)
    (* module type Core = sig *)

    (*   type ekey *)
    (*   type dkey *)

    (*   val of_secret   : Cstruct.t -> ekey * dkey *)
    (*   val e_of_secret : Cstruct.t -> ekey *)
    (*   val d_of_secret : Cstruct.t -> dkey *)

    (*   val key   : int array *)
    (*   val block : int *)

    (*   val encrypt : key:ekey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit *)
    (*   val decrypt : key:dkey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit *)
    (* end *)

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
      (** Construct the encryption key corresponding to [secret].

          @raise Invalid_argument if the length of [secret] is not in
          {{!key_sizes}[key_sizes]}. *)

      val key_sizes : int array
      (** Key sizes allowed with this cipher. *)

      val block_size : int
      (** The size of a single block. *)

      val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
      (** [encrypt ~key ~iv msg] is [msg] encrypted under [key], using [iv] as
          the CBC initialization vector.

          @raise Invalid_argument if [iv] is not [block_size], or [msg] is not
          [k * block_size] long. *)

      val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
      (** [decrypt ~key ~iv msg] is the inverse of [encrypt].

          @raise Invalid_argument if [iv] is not [block_size], or [msg] is not
          [k * block_size] long. *)

      val next_iv : iv:Cstruct.t -> Cstruct.t -> Cstruct.t
      (** [next_iv ~iv ciphertext] is the first [iv] {e following} the
          encryption that used [iv] to produce [ciphertext].

          For protocols which perform inter-message chaining, this is the [iv]
          for the next message.

          It is either [iv], when [len ciphertext = 0], or the last block of
          [ciphertext]. Note that

{[encrypt ~iv msg1 || encrypt ~iv:(next_iv ~iv (encrypt ~iv msg1)) msg2
  == encrypt ~iv (msg1 || msg2)]}

          @raise Invalid_argument if the length of [iv] is not [block_size], or
          the length of [ciphertext] is not [k * block_size] for some [k]. *)
    end

    (** {e Counter} mode. *)
    module type CTR = sig

      type key

      val of_secret : Cstruct.t -> key
      (** Construct the encryption key corresponding to [secret].

          @raise Invalid_argument if the length of [secret] is not in
          {{!key_sizes}[key_sizes]}. *)

      val key_sizes : int array
      (** Key sizes allowed with this cipher. *)

      val block_size : int
      (** The size of a single block. *)

      type ctr

      val stream : key:key -> ctr:ctr -> int -> Cstruct.t
      (** [stream ~key ~ctr n] is the raw keystream.

          Keystream is the concatenation of successive encrypted counter states.
          If [E(x)] is the single block [x] encrypted under [key], then keystream
          is the first [n] bytes of
          [E(ctr) || E(add ctr 1) || E(add ctr 2) || ...].

          Note that

{[stream ~key ~ctr (k * block_size) || stream ~key ~ctr:(add ctr k) x
  == stream ~key ~ctr (k * block_size + x)]}

          In other words, it is possible to restart a keystream at [block_size]
          boundaries by manipulating the counter. *)

      val encrypt : key:key -> ctr:ctr -> Cstruct.t -> Cstruct.t
      (** [encrypt ~key ~ctr msg] is
          [stream ~key ~ctr ~off (len msg) lxor msg]. *)

      val decrypt : key:key -> ctr:ctr -> Cstruct.t -> Cstruct.t
      (** [decrypt] is [encrypt]. *)

      val add_ctr : ctr -> int64 -> ctr

      val next_ctr : ctr:ctr -> Cstruct.t -> ctr
      (** [next_ctr ~ctr msg] is the state of the counter after encrypting or
          decrypting [msg] with the counter [ctr].

          For protocols which perform inter-message chaining, this is the
          counter for the next message.

          It is computed as [C.add ctr (ceil (len msg / block_size))]. Note that
          if [len msg1 = k * block_size],

{[encrypt ~ctr msg1 || encrypt ~ctr:(next_ctr ~ctr msg1) msg2
  == encrypt ~ctr (msg1 || msg2)]}

          *)

      val ctr_of_cstruct : Cstruct.t -> ctr
    end

    (** {e Galois/Counter Mode}. *)
    module type GCM = sig

      type key

      type result = { message : Cstruct.t ; tag : Cstruct.t }
      (** The transformed message, packed with the authentication tag. *)

      val of_secret : Cstruct.t -> key
      (** Construct the encryption key corresponding to [secret].

          @raise Invalid_argument if the length of [secret] is not in
          {{!key_sizes}[key_sizes]}. *)

      val key_sizes  : int array
      (** Key sizes allowed with this cipher. *)

      val block_size : int
      (** The size of a single block. *)

      val encrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
      (** [encrypt ~key ~iv ?adata msg] is the {{!result}[result]} containing
          [msg] encrypted under [key], with [iv] as the initialization vector,
          and the authentication tag computed over both [adata] and [msg]. *)

      val decrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
      (** [decrypt ~key ~iv ?adata msg] is the result containing the inversion
          of [encrypt] and the same authentication tag. *)
    end

    (** {e Counter with CBC-MAC} mode. *)
    module type CCM = sig

      type key

      val of_secret : maclen:int -> Cstruct.t -> key
      (** Construct the encryption key corresponding to [secret], that will
          produce authentication codes with the length [maclen].

          @raise Invalid_argument if the length of [secret] is not in
          {{!key_sizes}[key_sizes]} or [maclen] is not in [mac_sizes] *)

      val key_sizes  : int array
      (** Key sizes allowed with this cipher. *)

      val block_size : int
      (** The size of a single block. *)

      val mac_sizes  : int array
      (** [MAC] lengths allowed with this cipher. *)

      val encrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t
      (** [encrypt ~key ~nonce ?adata msg] is [msg] encrypted under [key] and
          [nonce], packed with authentication data computed over [msg] and
          [adata].

          @raise Invalid_argument if [nonce] is not between 7 and 13 bytes long.  *)

      val decrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t option
      (** [decrypt ~key ~nonce ?adata msg] is [Some text] when [msg] was
          produced by the corresponding [encrypt], or [None] otherwise.

          @raise Invalid_argument if [nonce] is not between 7 and 13 bytes long.  *)
    end
  end

  module AES : sig
(*     module Core : S.Core *)
    module ECB  : S.ECB
    module CBC  : S.CBC
    module CTR  : S.CTR with type ctr = int64 * int64
    module GCM  : S.GCM
    module CCM  : S.CCM
  end

  module DES : sig
(*     module Core : S.Core *)
    module ECB  : S.ECB
    module CBC  : S.CBC
    module CTR  : S.CTR with type ctr = int64
  end

  val accelerated : [`XOR | `AES | `GHASH] list
  (** Operations using non-portable, hardware-dependent implementation in
      this build of the library. *)
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
