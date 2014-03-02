
module type Hash_fn = sig
  val hmac_block  : int
  val digest_size : int
  val digest : Cstruct.t -> Cstruct.t
end

module Build ( H : Hash_fn ) = struct

  include H

  let rpad0 cs =
    let open Cstruct in
    let l   = len cs
    and cs' = create hmac_block in
    blit cs 0 cs' 0 l;
    for i = l to hmac_block - 1 do set_uint8 cs' i 0 done;
    cs'

  let create_with len x =
    let cs = Cstruct.create len in
    for i = 0 to len - 1 do Cstruct.set_uint8 cs i x done;
    cs

  let opad = create_with hmac_block 0x5c
  let ipad = create_with hmac_block 0x36

  let hmac ~key message =
    let open Cstruct_ in
    let key = if len key > hmac_block then digest key else key in
    let key = if len key < hmac_block then rpad0 key else key in
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

