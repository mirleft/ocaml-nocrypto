
module Rand = struct

  module type Rng = sig
    type g
    val block_size : int
    val generate   : ?g:g -> int -> Cstruct.t
  end

  module type N = sig

    type t
    type g

    val gen      : ?g:g -> t -> t
    val gen_bits : ?g:g -> int -> t
    val gen_r    : ?g:g -> t -> t -> t
  end

  module type Numeric = sig

    type g

    (* Generate a prime taking this many bits. First bit is 1. *)
    val prime : ?g:g -> bits:int -> Z.t

    (* Generate a prime pair g, p with p = 2g + 1. *)
    val safe_prime : ?g:g -> bits:int -> Z.t * Z.t

    module Int   : N with type g = g and type t = int
    module Int32 : N with type g = g and type t = int32
    module Int64 : N with type g = g and type t = int64
    module Z     : N with type g = g and type t = Z.t
  end

end

module type Hash = sig
  type t

  val digest_size : int

  val init : unit -> t
  val feed : t    -> Cstruct.t -> unit
  val get  : t    -> Cstruct.t

  val digest  : Cstruct.t      -> Cstruct.t
  val digestv : Cstruct.t list -> Cstruct.t
end

module type Hash_MAC = sig
  include Hash
  val hmac : key:Cstruct.t -> Cstruct.t -> Cstruct.t
end


module Block = struct

  module type Cipher_raw = sig

    type ekey
    type dkey
    val e_of_secret : Cstruct.t -> ekey
    val d_of_secret : Cstruct.t -> dkey

    val key_sizes  : int array
    val block_size : int
    val encrypt_block : key:ekey -> Cstruct.t -> Cstruct.t -> unit
    val decrypt_block : key:dkey -> Cstruct.t -> Cstruct.t -> unit
  end

  module type Cipher_base = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
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

  module type Counter = sig
    val increment : Cstruct.t -> unit
  end

end

module type Stream_cipher = sig
  type key
  type result = { message : Cstruct.t ; key : key }
  val of_secret : Cstruct.t -> key
  val encrypt : key:key -> Cstruct.t -> result
  val decrypt : key:key -> Cstruct.t -> result
end


