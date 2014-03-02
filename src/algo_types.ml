
module type Hash = sig

  val digest_size : int

  val digest : Cstruct.t -> Cstruct.t
  val hmac   : key:Cstruct.t -> Cstruct.t -> Cstruct.t
end

module type Stream_cipher = sig

  type key

  val of_secret : Cstruct.t -> key

  val encrypt : key:key -> Cstruct.t -> key * Cstruct.t
  val decrypt : key:key -> Cstruct.t -> key * Cstruct.t
end

module type Block_cipher = sig

  type key

  val of_secret  : Cstruct.t -> key
  val block_size : int

  val encrypt_ecb : key:key -> Cstruct.t -> Cstruct.t
  val decrypt_ecb : key:key -> Cstruct.t -> Cstruct.t

  val encrypt_cbc : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
  val decrypt_cbc : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
end
