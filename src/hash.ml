open Uncommon

module type T = sig

  type t

  val digest_size : int

  val init : unit -> t
  val feed : t    -> Cstruct.t -> unit
  val get  : t    -> Cstruct.t

  val digest  : Cstruct.t      -> Cstruct.t
  val digestv : Cstruct.t list -> Cstruct.t
  val hmac    : key:Cstruct.t -> Cstruct.t -> Cstruct.t
end

module type Foreign = sig

  open Native

  val init     : buffer -> unit
  val update   : buffer -> buffer -> int -> int -> unit
  val finalize : buffer -> buffer -> int -> unit
  val ctx_size : unit -> int
end

module type Desc = sig
  val block_size  : int
  val digest_size : int
end

module Core (F : Foreign) (D : Desc) = struct

  type t = Native.buffer

  let block_size  = D.block_size
  and digest_size = D.digest_size
  and ctx_size    = F.ctx_size ()

  let init () =
    let t = Native.buffer ctx_size in
    ( F.init t ; t )

  let feed t { Cstruct.buffer ; off ; len } =
    F.update t buffer off len

  let get t =
    let res = Cstruct.create digest_size in
    F.finalize t res.Cstruct.buffer res.Cstruct.off ;
    res

  let digest cs =
    let t = init () in ( feed t cs ; get t )

  let digestv css =
    let t = init () in ( List.iter (feed t) css ; get t )
end

module Hash_of (F : Foreign) (D : Desc) = struct

  open Cs

  include Core (F) (D)

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

module MD5 = Hash_of (Native.MD5) ( struct
  let (digest_size, block_size) = (16, 64)
end )

module SHA1 = Hash_of (Native.SHA1) ( struct
  let (digest_size, block_size) = (20, 64)
end )

module SHA224 = Hash_of (Native.SHA224) ( struct
  let (digest_size, block_size) = (28, 64)
end )

module SHA256 = Hash_of (Native.SHA256) ( struct
  let (digest_size, block_size) = (32, 64)
end )

module SHA384 = Hash_of (Native.SHA384) ( struct
  let (digest_size, block_size) = (48, 128)
end )

module SHA512 = Hash_of (Native.SHA512) ( struct
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
