
module type Hash_fn = sig
  val block_size  : int
  val digest_size : int
  val digest : Cstruct.t -> Cstruct.t
end

let cs_fun_of_byte_fun f cs = Cstruct.(of_bigarray (f (to_bigarray cs)))

module Hmac ( H : Hash_fn ) = struct

  include H

  let opad = Cstruct_.create_with block_size 0x5c
  let ipad = Cstruct_.create_with block_size 0x36

  let hmac ~key message =
    let open Cstruct_ in
    let key = if len key > block_size then digest key else key in
    let key = if len key < block_size then rpad key block_size 0 else key in
    let outer = xor key opad
    and inner = xor key ipad in
    digest (outer <> digest (inner <> message))

end

module MD5 = Hmac ( struct
  let block_size  = 64
  let digest_size = 16
  let digest      = cs_fun_of_byte_fun Native.md5
end )

module SHA1 = Hmac ( struct
  let block_size  = 64
  let digest_size = 20
  let digest      = cs_fun_of_byte_fun Native.sha1
end )

module SHA224 = struct
  let digest_size = 28
  let digest      = cs_fun_of_byte_fun Native.sha224
end

module SHA256 = Hmac ( struct
  let digest_size = 32
  let block_size  = 64
  let digest      = cs_fun_of_byte_fun Native.sha256
end )

module SHA384 = Hmac ( struct
  let digest_size = 48
  let block_size  = 128
  let digest      = cs_fun_of_byte_fun Native.sha384
end )

module SHA512 = Hmac ( struct
  let digest_size = 64
  let block_size  = 128
  let digest      = cs_fun_of_byte_fun Native.sha512
end )
