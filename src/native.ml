
open Bigarray

let buffer = Array1.create char c_layout


type buffer = (char, int8_unsigned_elt, c_layout) Array1.t

(* Readability. *)
type off    = int
type size   = int
type secret = buffer
type key    = buffer
type ctx    = buffer


module AES = struct
  external enc      : buffer -> off -> buffer -> off -> key -> int -> size -> unit = "caml_nc_aes_enc_bc" "caml_nc_aes_enc" "noalloc"
  external dec      : buffer -> off -> buffer -> off -> key -> int -> size -> unit = "caml_nc_aes_dec_bc" "caml_nc_aes_dec" "noalloc"
  external derive_e : secret -> off -> key -> int -> unit = "caml_nc_aes_derive_e_key" "noalloc"
  external derive_d : secret -> off -> key -> int -> key option -> unit = "caml_nc_aes_derive_d_key" "noalloc"
  external rk_s     : int  -> int = "caml_nc_aes_rk_size" "noalloc"
  external mode     : unit -> int = "caml_nc_aes_mode" "noalloc"
end

module DES = struct
  external ddes    : buffer -> off -> buffer -> off -> int -> unit = "caml_nc_des_ddes" "noalloc"
  external des3key : secret -> off -> int -> unit = "caml_nc_des_des3key" "noalloc"
  external cp3key  : key -> unit = "caml_nc_des_cp3key" "noalloc"
  external use3key : key -> unit = "caml_nc_des_use3key" "noalloc"
  external k_s     : unit -> int = "caml_nc_des_key_size" "noalloc"
end

module MD5 = struct
  external init     : ctx -> unit = "caml_nc_md5_init" "noalloc"
  external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_md5_update" "noalloc"
  external finalize : ctx -> buffer -> off -> unit = "caml_nc_md5_finalize" "noalloc"
  external ctx_size : unit -> int = "caml_nc_md5_ctx_size" "noalloc"
end

module SHA1 = struct
  external init     : ctx -> unit = "caml_nc_sha1_init" "noalloc"
  external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha1_update" "noalloc"
  external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha1_finalize" "noalloc"
  external ctx_size : unit -> int = "caml_nc_sha1_ctx_size" "noalloc"
end

module SHA224 = struct
  external init     : ctx -> unit = "caml_nc_sha224_init" "noalloc"
  external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha224_update" "noalloc"
  external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha224_finalize" "noalloc"
  external ctx_size : unit -> int = "caml_nc_sha224_ctx_size" "noalloc"
end

module SHA256 = struct
  external init     : ctx -> unit = "caml_nc_sha256_init" "noalloc"
  external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha256_update" "noalloc"
  external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha256_finalize" "noalloc"
  external ctx_size : unit -> int = "caml_nc_sha256_ctx_size" "noalloc"
end

module SHA384 = struct
  external init     : ctx -> unit = "caml_nc_sha384_init" "noalloc"
  external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha384_update" "noalloc"
  external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha384_finalize" "noalloc"
  external ctx_size : unit -> int = "caml_nc_sha384_ctx_size" "noalloc"
end

module SHA512 = struct
  external init     : ctx -> unit = "caml_nc_sha512_init" "noalloc"
  external update   : ctx -> buffer -> off -> size -> unit = "caml_nc_sha512_update" "noalloc"
  external finalize : ctx -> buffer -> off -> unit = "caml_nc_sha512_finalize" "noalloc"
  external ctx_size : unit -> int = "caml_nc_sha512_ctx_size" "noalloc"
end

(* XXX TODO
 * Unsolved: bounds-checked XORs are slowing things down considerably... *)
external xor_into : buffer -> off -> buffer -> off -> size -> unit = "caml_nc_xor_into" "noalloc"

external count8be  : buffer -> off -> buffer -> off -> size -> unit = "caml_nc_count_8_be" "noalloc"
external count16be : buffer -> off -> buffer -> off -> size -> unit = "caml_nc_count_16_be" "noalloc"
