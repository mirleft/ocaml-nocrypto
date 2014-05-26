open Common

module type T     = sig include Algo_types.Hash end
module type T_MAC = sig include Algo_types.Hash_MAC end

module type Base_hash = sig
  type t
  val block_size : int
  val digest_size : int
  val init : unit -> t
  val feed : t    -> Native.ba -> unit
  val get  : t    -> Native.ba
end

module Full_hash (H : Base_hash) = struct

  type t = H.t

  let block_size  = H.block_size
  let digest_size = H.digest_size

  let init       = H.init
  let feed st cs = H.feed st (Cstruct.to_bigarray cs)
  let get st     = Cstruct.of_bigarray (H.get st)

  let digestv css =
    let st = init () in ( List.iter (feed st) css ; get st )

  let digest cs = digestv [cs]
end

module Full_hash_hmac ( H0 : Base_hash ) = struct

  open Cs

  module H = Full_hash (H0)
  include H

  let opad = create_with block_size 0x5c
  let ipad = create_with block_size 0x36

  let rec norm key =
    match compare (Cstruct.len key) block_size with
    |  1 -> norm (digest key)
    | -1 -> rpad key block_size 0
    |  _ -> key

  let hmac ~key message =
    let key = norm key in
    let outer = xor key opad
    and inner = xor key ipad in
    digest (outer <> digest (inner <> message))

end

open Native

module MD5 = Full_hash_hmac ( struct
  type t = ba
  let (digest_size, block_size) = (16, 64)
  let init = md5_init and feed = md5_feed and get = md5_get
end )

module SHA1 = Full_hash_hmac ( struct
  type t = ba
  let (digest_size, block_size) = (20, 64)
  let init = sha1_init and feed = sha1_feed and get = sha1_get
end )

module SHA224 = Full_hash ( struct
  type t = ba
  let (digest_size, block_size) = (28, 64)
  let init = sha224_init and feed = sha224_feed and get = sha224_get
end )

module SHA256 = Full_hash_hmac ( struct
  type t = ba
  let (digest_size, block_size) = (32, 64)
  let init = sha256_init and feed = sha256_feed and get = sha256_get
end )

module SHA384 = Full_hash_hmac ( struct
  type t = ba
  let (digest_size, block_size) = (48, 128)
  let init = sha384_init and feed = sha384_feed and get = sha384_get
end )

module SHA512 = Full_hash_hmac ( struct
  type t = ba
  let (digest_size, block_size) = (64, 128)
  let init = sha512_init and feed = sha512_feed and get = sha512_get
end )

module SHAd256 = struct
  include SHA256
  let get    = SHA256.(o digest get)
  let digest = SHA256.(o digest digest)
  let digestv css = let s = init () in ( List.iter (feed s) css ; get s )
end
