
open Bigarray
type ba = (char, int8_unsigned_elt, c_layout) Array1.t

external md5_init    : unit -> ba       = "caml_nc_init_MD5"
external md5_feed    : ba -> ba -> unit = "caml_nc_feed_MD5"
external md5_get     : ba -> ba         = "caml_nc_get_MD5"
external sha1_init   : unit -> ba       = "caml_nc_init_SHA1"
external sha1_feed   : ba -> ba -> unit = "caml_nc_feed_SHA1"
external sha1_get    : ba -> ba         = "caml_nc_get_SHA1"
external sha224_init : unit -> ba       = "caml_nc_init_SHA224"
external sha224_feed : ba -> ba -> unit = "caml_nc_feed_SHA224"
external sha224_get  : ba -> ba         = "caml_nc_get_SHA224"
external sha256_init : unit -> ba       = "caml_nc_init_SHA256"
external sha256_feed : ba -> ba -> unit = "caml_nc_feed_SHA256"
external sha256_get  : ba -> ba         = "caml_nc_get_SHA256"
external sha384_init : unit -> ba       = "caml_nc_init_SHA384"
external sha384_feed : ba -> ba -> unit = "caml_nc_feed_SHA384"
external sha384_get  : ba -> ba         = "caml_nc_get_SHA384"
external sha512_init : unit -> ba       = "caml_nc_init_SHA512"
external sha512_feed : ba -> ba -> unit = "caml_nc_feed_SHA512"
external sha512_get  : ba -> ba         = "caml_nc_get_SHA512"

external aes_create_enc   : ba -> ba = "caml_nc_aes_create_Enc_key"
external aes_create_dec   : ba -> ba = "caml_nc_aes_create_Dec_key"
external aes_encrypt_into : ba -> ba -> ba -> unit = "caml_nc_aes_Enc"
external aes_decrypt_into : ba -> ba -> ba -> unit = "caml_nc_aes_Dec"
