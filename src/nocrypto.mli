
open Algo_types

module Hash : sig
  module MD5    : Hash_MAC
  module SHA1   : Hash_MAC
  module SHA224 : Hash
  module SHA256 : Hash_MAC
  module SHA384 : Hash_MAC
  module SHA512 : Hash_MAC
end

module Stream : sig
  module ARC4 : Stream_cipher
end

module Block : sig
  module AES : sig
    include Block_cipher
    include ECB_cipher with type key := key
    include CBC_cipher with type key := key
    include GCM_cipher with type key := key
  end
end

module Rsa : sig

  type pub
  type priv

  val pub            : e:Z.t -> n:Z.t -> pub
  val pub_of_cstruct : e:Cstruct.t -> n:Cstruct.t -> pub

  val priv :
    e:Z.t -> d:Z.t -> n:Z.t -> p:Z.t -> q:Z.t -> dp:Z.t -> dq:Z.t -> q':Z.t -> priv

  val priv_of_cstruct :
    e:Cstruct.t -> d:Cstruct.t -> n:Cstruct.t ->
    p:Cstruct.t -> q:Cstruct.t ->
    dp:Cstruct.t -> dq:Cstruct.t -> q':Cstruct.t ->
    priv

  val pub_of_priv : priv -> pub

  val priv_of_primes : e:Z.t -> p:Z.t -> q:Z.t -> priv

  val encrypt_z : key:pub  -> Z.t -> Z.t
  val decrypt_z : key:priv -> Z.t -> Z.t
  val encrypt   : key:pub  -> Cstruct.t -> Cstruct.t
  val decrypt   : key:priv -> Cstruct.t -> Cstruct.t

  val generate : ?e:Z.t -> int -> priv
  val print_key : priv -> unit
end
