
open Bigarray

type buffer = (char, int8_unsigned_elt, c_layout) Array1.t

let buffer = Array1.create char c_layout

module AES = struct
  external derive_e : buffer -> int -> buffer -> int -> unit = "caml_nc_aes_derive_e_key" "noalloc"
  external derive_d : buffer -> int -> buffer -> int -> buffer option -> unit = "caml_nc_aes_derive_d_key" "noalloc"
  external enc    : buffer -> int -> int -> buffer -> int -> buffer -> int -> unit = "caml_nc_aes_enc_bc" "caml_nc_aes_enc" "noalloc"
  external dec    : buffer -> int -> int -> buffer -> int -> buffer -> int -> unit = "caml_nc_aes_dec_bc" "caml_nc_aes_dec" "noalloc"
  external rk_s   : int -> int = "caml_nc_aes_rk_size" "noalloc"
end

module DES = struct
  external des3key : buffer -> int -> int -> unit                   = "caml_nc_des_des3key"  "noalloc"
  external cp3key  : buffer -> unit                                 = "caml_nc_des_cp3key"   "noalloc"
  external use3key : buffer -> unit                                 = "caml_nc_des_use3key"  "noalloc"
  external ddes    : int -> buffer -> int -> buffer -> int -> unit  = "caml_nc_des_ddes"     "noalloc"
  external k_s     : unit -> int                                    = "caml_nc_des_key_size" "noalloc"
end

(* XXX TODO
 * Unsolved: bounds-checked XORs are slowing things down considerably... *)
external xor_into : buffer -> int -> buffer -> int -> int -> unit = "caml_nc_xor_into" "caml_nc_xor_into" "noalloc"

module Conv = struct

  open Ctypes

  let bigstring_create =
    Bigarray.(Array1.create char c_layout)

  let bs_ptr bs = bigarray_start array1 bs

  let cs_ptr cs =
    bigarray_start array1 cs.Cstruct.buffer +@ cs.Cstruct.off

  let cs_len_size_t cs =
    Unsigned.Size_t.of_int cs.Cstruct.len

  let cs_len32 cs =
    Unsigned.UInt32.of_int cs.Cstruct.len

  let allocate_voidp ~count =
    Ctypes.(to_voidp @@ allocate_n uint8_t ~count)

end

module Bindings = Bindings.Make (Nocrypto_generated)
