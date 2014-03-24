
module Rand = struct

  module type Rng = sig
    type g
    val block_size : int
    val generate   : ?g:g -> int -> Cstruct.t
  end

  module type N = sig

    module Rng : Rng
    module N   : Numeric.T

    val gen      : ?g:Rng.g -> N.t -> N.t
    val gen_bits : ?g:Rng.g -> int -> N.t
    val gen_r    : ?g:Rng.g -> N.t -> N.t -> N.t
  end

  module type Numeric = sig

    module Rng : Rng

    (* Generate a prime taking this many bits. First bit is 1. *)
    val prime      : ?g:Rng.g -> bits:int -> Z.t

    (* Generate a prime pair g, p with p = 2g + 1. *)
    val safe_prime : ?g:Rng.g -> bits:int -> Z.t * Z.t

    module Int   : N with module Rng = Rng and module N = Numeric.Int
    module Int32 : N with module Rng = Rng and module N = Numeric.Int32
    module Int64 : N with module Rng = Rng and module N = Numeric.Int64
    module Z     : N with module Rng = Rng and module N = Numeric.Z
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

    val block_size : int

    val encrypt_block : ekey -> Cstruct.t -> Cstruct.t -> unit
    val decrypt_block : dkey -> Cstruct.t -> Cstruct.t -> unit
  end

  module type Cipher_base = sig
    type key
    val of_secret : Cstruct.t -> key

    val block_size : int

    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
  end

  module type Mode = sig
    type key
    val of_secret : Cstruct.t -> key
    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
  end

  module type Mode_CBC = sig
    type key
    type result = { message : Cstruct.t ; iv : Cstruct.t }
    val of_secret : Cstruct.t -> key
    val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
    val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
  end

  module type Mode_GCM = sig
    type key
    type result = { message : Cstruct.t ; tag : Cstruct.t }
    val of_secret : Cstruct.t -> key
    val encrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
    val decrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
  end

end

module type Stream_cipher = sig
  type key
  val of_secret : Cstruct.t -> key
  val encrypt : key:key -> Cstruct.t -> key * Cstruct.t
  val decrypt : key:key -> Cstruct.t -> key * Cstruct.t
end


