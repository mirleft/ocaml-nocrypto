open Algo_types

module type T     = Hash
module type T_MAC = Hash_MAC

module MD5    : Hash_MAC
module SHA1   : Hash_MAC
module SHA224 : Hash
module SHA256 : Hash_MAC
module SHA384 : Hash_MAC
module SHA512 : Hash_MAC
module SHAd256 : Hash

