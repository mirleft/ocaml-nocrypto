(* module Base64 = Nocrypto_base.Base64 *)
(* module Uncommon = Nocrypto_base.Uncommon *)

module Hash          = Nocrypto_hash
module Cipher_block  = Nocrypto_cipher.Cipher_block
module Cipher_stream = Nocrypto_cipher.Cipher_stream
module Rng           = NoRng
module Rsa           = Nocrypto_pk.Rsa
module Dsa           = Nocrypto_pk.Dsa
module Dh            = Nocrypto_pk.Dh
