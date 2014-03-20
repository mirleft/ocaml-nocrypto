open Algo_types

(* XXX *)
module AES_raw : sig
  type key
  val create_e : Cstruct.t -> key
  val create_d : Cstruct.t -> key
  val encrypt_blk : key -> Cstruct.t -> Cstruct.t -> unit
  val decrypt_blk : key -> Cstruct.t -> Cstruct.t -> unit
end

module AES : sig
  include Block_cipher
  include ECB_cipher with type key := key
  include CBC_cipher with type key := key
  include GCM_cipher with type key := key
end
