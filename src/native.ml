
open Bigarray

type bigstring = (char, int8_unsigned_elt, c_layout) Array1.t

type ba = bigstring

external md5_init    : unit -> ba       = "caml_nc_init_MD5"
external md5_feed    : ba -> ba -> unit = "caml_nc_feed_MD5"    "noalloc"
external md5_get     : ba -> ba         = "caml_nc_get_MD5"
external sha1_init   : unit -> ba       = "caml_nc_init_SHA1"
external sha1_feed   : ba -> ba -> unit = "caml_nc_feed_SHA1"   "noalloc"
external sha1_get    : ba -> ba         = "caml_nc_get_SHA1"
external sha224_init : unit -> ba       = "caml_nc_init_SHA224"
external sha224_feed : ba -> ba -> unit = "caml_nc_feed_SHA224" "noalloc"
external sha224_get  : ba -> ba         = "caml_nc_get_SHA224"
external sha256_init : unit -> ba       = "caml_nc_init_SHA256"
external sha256_feed : ba -> ba -> unit = "caml_nc_feed_SHA256" "noalloc"
external sha256_get  : ba -> ba         = "caml_nc_get_SHA256"
external sha384_init : unit -> ba       = "caml_nc_init_SHA384"
external sha384_feed : ba -> ba -> unit = "caml_nc_feed_SHA384" "noalloc"
external sha384_get  : ba -> ba         = "caml_nc_get_SHA384"
external sha512_init : unit -> ba       = "caml_nc_init_SHA512"
external sha512_feed : ba -> ba -> unit = "caml_nc_feed_SHA512" "noalloc"
external sha512_get  : ba -> ba         = "caml_nc_get_SHA512"

external aes_create_enc   : ba -> ba               = "caml_nc_aes_create_Enc_key"
external aes_create_dec   : ba -> ba               = "caml_nc_aes_create_Dec_key"
external aes_encrypt_into : ba -> ba -> ba -> unit = "caml_nc_aes_Enc" "noalloc"
external aes_decrypt_into : ba -> ba -> ba -> unit = "caml_nc_aes_Dec" "noalloc"

external des3_create_key   : ba -> int -> ba        = "caml_nc_des_create_key"
external des3_xform_into   : ba -> ba -> ba -> unit = "caml_nc_des_transform"  "noalloc"
external des3_xform_into2  : ba -> ba -> ba -> unit = "caml_nc_des_transform2" "noalloc"

open Ctypes
open PosixTypes

module Conv = struct

  let bigstring_create = Bigarray.(Array1.create char c_layout)

  let bs_ptr bs = bigarray_start array1 bs

  let cs_ptr cs =
    bigarray_start array1 Cstruct.(to_bigarray cs)
(*     bigarray_start array1 cs.Cstruct.buffer +@ cs.Cstruct.off *) (* XXX *)

  let cs_len_size_t cs = Unsigned.Size_t.of_int cs.Cstruct.len

end

module Bindings (F : sig
  type 'a fn
  val foreign : string -> ('a -> 'b) Ctypes.fn -> ('a -> 'b) fn
end) = struct


end
