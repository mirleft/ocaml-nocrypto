open Uncommon

module type T     = sig include Module_types.Hash end
module type T_MAC = sig include Module_types.Hash_MAC end

module type Base_hash = sig

  open Ctypes

  val block_size  : int
  val digest_size : int
  val ssize       : unit -> Unsigned.size_t
  val init   : unit ptr -> unit
  val update : unit ptr -> char ptr -> PosixTypes.size_t -> unit
  val final  : char ptr -> unit ptr -> unit
end

module Full_hash (H : Base_hash) = struct

  open Native

  type t = unit Ctypes.ptr

  let block_size  = H.block_size
  and digest_size = H.digest_size
  and struct_size = Unsigned.Size_t.to_int H.(ssize ())

  let init () =
    let t = Conv.allocate_voidp struct_size in
    ( H.init t; t )

  let feed t cs =
    H.update t Conv.(cs_ptr cs) Conv.(cs_len_size_t cs)

  let get t =
    let res = Cstruct.create H.digest_size in
    ( H.final Conv.(cs_ptr res) t; res )

  let digestv css =
    let t = init () in ( List.iter (feed t) css ; get t )

  let digest cs =
    let t = init () in ( feed t cs ; get t )

end

module Full_hash_hmac (H : Base_hash) = struct

  open Cs

  include Full_hash (H)

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

module Bindings = Native.Bindings

module MD5 = Full_hash_hmac ( struct
  include Bindings.MD5
  let (digest_size, block_size) = (16, 64)
end )

module SHA1 = Full_hash_hmac ( struct
  include Bindings.SHA1
  let (digest_size, block_size) = (20, 64)
end )

module SHA224 = Full_hash ( struct
  include Bindings.SHA224
  let (digest_size, block_size) = (28, 64)
end )

module SHA256 = Full_hash_hmac ( struct
  include Bindings.SHA256
  let (digest_size, block_size) = (32, 64)
end )

module SHA384 = Full_hash_hmac ( struct
  include Bindings.SHA384
  let (digest_size, block_size) = (48, 128)
end )

module SHA512 = Full_hash_hmac ( struct
  include Bindings.SHA512
  let (digest_size, block_size) = (64, 128)
end )

module SHAd256 = struct
  include SHA256
  let get    = SHA256.(o digest get)
  let digest = SHA256.(o digest digest)
  let digestv css = let s = init () in ( List.iter (feed s) css ; get s )
end

type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ]
type mac  = [ `MD5 | `SHA1 | `SHA256 | `SHA384 | `SHA512 ]

let digest = function
  | `MD5    -> MD5.digest
  | `SHA1   -> SHA1.digest
  | `SHA224 -> SHA224.digest
  | `SHA256 -> SHA256.digest
  | `SHA384 -> SHA384.digest
  | `SHA512 -> SHA512.digest

let mac fn ~key cs =
  match fn with
  | `MD5    -> MD5.hmac ~key cs
  | `SHA1   -> SHA1.hmac ~key cs
  | `SHA256 -> SHA256.hmac ~key cs
  | `SHA384 -> SHA384.hmac ~key cs
  | `SHA512 -> SHA512.hmac ~key cs
