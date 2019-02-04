open Nocrypto_uncommon

module Native = struct

  open Bigarray

  type buffer = (char, int8_unsigned_elt, c_layout) Array1.t
  type off   = int
  type size  = int
  type ctx   = bytes

  module MD5 = struct
    external init     : ctx -> unit = "caml_nc_md5_init" [@@noalloc]
    external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_md5_update" [@@noalloc]
    external finalize : ctx -> buffer -> off -> unit = "caml_nc_md5_finalize" [@@noalloc]
    external ctx_size : unit -> int = "caml_nc_md5_ctx_size" [@@noalloc]
  end

  module SHA1 = struct
    external init     : ctx -> unit = "caml_nc_sha1_init" [@@noalloc]
    external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha1_update" [@@noalloc]
    external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha1_finalize" [@@noalloc]
    external ctx_size : unit -> int = "caml_nc_sha1_ctx_size" [@@noalloc]
  end

  module SHA224 = struct
    external init     : ctx -> unit = "caml_nc_sha224_init" [@@noalloc]
    external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha224_update" [@@noalloc]
    external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha224_finalize" [@@noalloc]
    external ctx_size : unit -> int = "caml_nc_sha224_ctx_size" [@@noalloc]
  end

  module SHA256 = struct
    external init     : ctx -> unit = "caml_nc_sha256_init" [@@noalloc]
    external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha256_update" [@@noalloc]
    external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha256_finalize" [@@noalloc]
    external ctx_size : unit -> int = "caml_nc_sha256_ctx_size" [@@noalloc]
  end

  module SHA384 = struct
    external init     : ctx -> unit = "caml_nc_sha384_init" [@@noalloc]
    external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha384_update" [@@noalloc]
    external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha384_finalize" [@@noalloc]
    external ctx_size : unit -> int = "caml_nc_sha384_ctx_size" [@@noalloc]
  end

  module SHA512 = struct
    external init     : ctx -> unit = "caml_nc_sha512_init" [@@noalloc]
    external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha512_update" [@@noalloc]
    external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha512_finalize" [@@noalloc]
    external ctx_size : unit -> int = "caml_nc_sha512_ctx_size" [@@noalloc]
  end

end

type digest = Cstruct.t

type 'a iter = ('a -> unit) -> unit

type 'a or_digest = [ `Message of 'a | `Digest of digest ]

module type S = sig

  val digest_size : int

  type t

  val empty : t
  val feed  : t -> Cstruct.t -> t
  val get   : t -> Cstruct.t

  val digest  : Cstruct.t -> digest
  val hmac    : key:Cstruct.t -> Cstruct.t -> digest

  val feedi   : t -> Cstruct.t iter -> t
  val digesti : Cstruct.t iter -> digest
  val hmaci   : key:Cstruct.t -> Cstruct.t iter -> digest
end

module type Foreign = sig

  open Native

  val init     : ctx -> unit
  val update   : ctx -> buffer -> int -> int -> unit
  val finalize : ctx -> buffer -> int -> unit
  val ctx_size : unit -> int
end

module type Desc = sig
  val block_size  : int
  val digest_size : int
end

module Core (F : Foreign) (D : Desc) = struct

  type t = Native.ctx

  include D

  let empty = Bytes.create (F.ctx_size ())

  let _ = F.init empty

  let update t { Cstruct.buffer ; off ; len } =
    F.update t buffer off len

  let finalize t =
    let res = Cstruct.create digest_size in
    F.finalize t res.Cstruct.buffer res.Cstruct.off ;
    res

  let dup = Bytes.copy

  let get t = dup t |> finalize

  let feed t cs = let t = dup t in (update t cs ; t)

  let feedi t iter = let t = dup t in (iter (update t) ; t)

  let digest cs = feed empty cs |> finalize

  let digesti iter = feedi empty iter |> finalize
end

module Hash_of (F : Foreign) (D : Desc) = struct

  open Cs

  include Core (F) (D)

  let opad = create ~init:0x5c block_size
  let ipad = create ~init:0x36 block_size

  let rec norm key =
    match compare (Cstruct.len key) block_size with
    |  1 -> norm (digest key)
    | -1 -> rpad key block_size 0
    |  _ -> key

  let hmaci ~key iter =
    let key = norm key in
    let outer = key lxor opad
    and inner = key lxor ipad in
    let rest = digesti (fun f -> f inner; iter f) in
    digesti (fun f -> f outer; f rest)

  let hmac ~key message = hmaci ~key (fun f -> f message)
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

type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ]

let md5    = (module MD5    : S)
and sha1   = (module SHA1   : S)
and sha224 = (module SHA224 : S)
and sha256 = (module SHA256 : S)
and sha384 = (module SHA384 : S)
and sha512 = (module SHA512 : S)

let module_of = function
  | `MD5    -> md5    | `SHA1   -> sha1   | `SHA224 -> sha224
  | `SHA256 -> sha256 | `SHA384 -> sha384 | `SHA512 -> sha512

let digest hash      = let module H = (val (module_of hash)) in H.digest
let digesti hash     = let module H = (val (module_of hash)) in H.digesti
let mac hash         = let module H = (val (module_of hash)) in H.hmac
let maci hash        = let module H = (val (module_of hash)) in H.hmaci
let digest_size hash = let module H = (val (module_of hash)) in H.digest_size

module Digest_or (H : S) = struct
  let digest_or = function
    | `Message msg   -> H.digest msg
    | `Digest digest ->
        let n = digest.Cstruct.len and m = H.digest_size in
        if n = m then digest else
          invalid_arg "(`Digest _): %d bytes, expecting %d" n m
end

let digest_or ~hash =
  let module H = (val (module_of hash)) in
  let module D = Digest_or (H) in
  D.digest_or

