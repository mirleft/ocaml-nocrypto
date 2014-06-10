
module type T     = sig include Algo_types.Hash end
module type T_MAC = sig include Algo_types.Hash_MAC end

module MD5     : T_MAC
module SHA1    : T_MAC
module SHA224  : T
module SHA256  : T_MAC
module SHA384  : T_MAC
module SHA512  : T_MAC
module SHAd256 : T

type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ]
type mac  = [ `MD5 | `SHA1 | `SHA256 | `SHA384 | `SHA512 ]

val digest : [< hash ] -> Cstruct.t -> Cstruct.t
val mac    : [< mac ] -> key:Cstruct.t -> Cstruct.t -> Cstruct.t
