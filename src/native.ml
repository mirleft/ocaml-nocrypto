
open Bigarray
type ba = (char, int8_unsigned_elt, c_layout) Array1.t

external md5    : ba -> ba = "caml_nc_MD5"
external sha1   : ba -> ba = "caml_nc_SHA1"
external sha224 : ba -> ba = "caml_nc_SHA224"
external sha256 : ba -> ba = "caml_nc_SHA256"
external sha384 : ba -> ba = "caml_nc_SHA384"
external sha512 : ba -> ba = "caml_nc_SHA512"

external aes_create_enc   : ba -> ba = "caml_nc_aes_create_Enc_key"
external aes_create_dec   : ba -> ba = "caml_nc_aes_create_Dec_key"
external aes_encrypt_into : int -> ba -> ba -> ba -> unit = "caml_nc_aes_Enc"
external aes_decrypt_into : int -> ba -> ba -> ba -> unit = "caml_nc_aes_Dec"
