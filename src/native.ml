
open Bigarray
type ba = (char, int8_unsigned_elt, c_layout) Array1.t

external sha1 : ba -> ba = "caml_nc_sha1"
external md5  : ba -> ba = "caml_nc_md5"
external aes_create_enc : ba -> ba = "caml_nc_aes_create_enc_key"
external aes_create_dec : ba -> ba = "caml_nc_aes_create_dec_key"
external aes_encrypt_into : int -> ba -> ba -> ba -> unit = "caml_nc_aes_encrypt"
external aes_decrypt_into : int -> ba -> ba -> ba -> unit = "caml_nc_aes_decrypt"
