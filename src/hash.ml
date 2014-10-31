open Uncommon

module type T = sig include Module_types.Hash end

module type Base_hash = sig

  open Ctypes

  val block_size  : int
  val digest_size : int
  val ssize       : unit -> Unsigned.size_t
  val init   : unit ptr -> unit
  val update : unit ptr -> char ptr -> Unsigned.UInt32.t -> unit
  val final  : unit ptr -> char ptr -> unit
end

module Wrap_native (H : Base_hash) = struct

  open Native

  type t = unit Ctypes.ptr

  let block_size  = H.block_size
  and digest_size = H.digest_size
  and struct_size = Unsigned.Size_t.to_int H.(ssize ())

  let init () =
    let t = Conv.allocate_voidp ~count:struct_size in
    ( H.init t; t )

  let feed t cs =
    H.update t Conv.(cs_ptr cs) Conv.(cs_len32 cs)

  let get t =
    let res = Cstruct.create H.digest_size in
    ( H.final t Conv.(cs_ptr res); res )

  let digestv css =
    let t = init () in ( List.iter (feed t) css ; get t )

  let digest cs =
    let t = init () in ( feed t cs ; get t )

end

module Hash_of (H : Base_hash) = struct

  open Cs

  include Wrap_native (H)

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
    digestv [ outer ; digestv [ inner ; message ] ]
end

module Bindings = Native.Bindings

module MD5 = Hash_of ( struct
  include Bindings.MD5
  let (digest_size, block_size) = (16, 64)
end )

module SHA1 = Hash_of ( struct
  include Bindings.SHA1
  let (digest_size, block_size) = (20, 64)
end )

module SHA224 = Hash_of ( struct
  include Bindings.SHA224
  let (digest_size, block_size) = (28, 64)
end )

module SHA256 = Hash_of ( struct
  include Bindings.SHA256
  let (digest_size, block_size) = (32, 64)
end )

module SHA384 = Hash_of ( struct
  include Bindings.SHA384
  let (digest_size, block_size) = (48, 128)
end )

module SHA512 = Hash_of ( struct
  include Bindings.SHA512
  let (digest_size, block_size) = (64, 128)
end )

module SHAd256 = struct
  include SHA256
  let get    = SHA256.(digest &. get)
  let digest = SHA256.(digest &. digest)
  let digestv css = let s = init () in ( List.iter (feed s) css ; get s )
end


type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ] with sexp

let digest = function
  | `MD5    -> MD5.digest
  | `SHA1   -> SHA1.digest
  | `SHA224 -> SHA224.digest
  | `SHA256 -> SHA256.digest
  | `SHA384 -> SHA384.digest
  | `SHA512 -> SHA512.digest

let mac = function
  | `MD5    -> MD5.hmac
  | `SHA1   -> SHA1.hmac
  | `SHA224 -> SHA224.hmac
  | `SHA256 -> SHA256.hmac
  | `SHA384 -> SHA384.hmac
  | `SHA512 -> SHA512.hmac

let digest_size = function
  | `MD5    -> MD5.digest_size
  | `SHA1   -> SHA1.digest_size
  | `SHA224 -> SHA224.digest_size
  | `SHA256 -> SHA256.digest_size
  | `SHA384 -> SHA384.digest_size
  | `SHA512 -> SHA512.digest_size

let module_of = function
  | `MD5    -> (module MD5 : T)
  | `SHA1   -> (module SHA1 : T)
  | `SHA224 -> (module SHA224 : T)
  | `SHA256 -> (module SHA256 : T)
  | `SHA384 -> (module SHA384 : T)
  | `SHA512 -> (module SHA512 : T)
