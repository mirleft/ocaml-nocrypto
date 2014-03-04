
module type Hash_fn = sig
  val hmac_block  : int
  val digest_size : int
  val digest : Cstruct.t -> Cstruct.t
end

module Build ( H : Hash_fn ) = struct

  include H

  let opad = Cstruct_.create_with hmac_block 0x5c
  let ipad = Cstruct_.create_with hmac_block 0x36

  let hmac ~key message =
    let open Cstruct_ in
    let key = if len key > hmac_block then digest key else key in
    let key = if len key < hmac_block then rpad key hmac_block 0 else key in
    let outer = xor key opad
    and inner = xor key ipad in
    digest (outer <> digest (inner <> message))

end

module SHA1 = Build ( struct
  let hmac_block  = 64
  let digest_size = 20
  let digest cs   =
    Cstruct.(of_bigarray (Native.sha1 (to_bigarray cs)))
end )

module MD5 = Build ( struct
  let hmac_block  = 64
  let digest_size = 16
  let digest cs   =
    Cstruct.(of_bigarray (Native.md5 (to_bigarray cs)))
end )

