
module type Hash = sig
  val digest_size : int
  val digest      : Cstruct.t -> Cstruct.t
end

module type Hash_MAC = sig
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
end

module type ECB_cipher = sig
  type key
  val encrypt_ecb : key:key -> Cstruct.t -> Cstruct.t
  val decrypt_ecb : key:key -> Cstruct.t -> Cstruct.t
end

module type CBC_cipher = sig
  type key
  val encrypt_cbc : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
  val decrypt_cbc : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
end

module type GCM_cipher = sig
  type key
  val encrypt_gcm : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
  val decrypt_gcm : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t * Cstruct.t
end
