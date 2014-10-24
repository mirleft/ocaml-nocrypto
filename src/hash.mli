
module type T = sig include Module_types.Hash end

module MD5     : T
module SHA1    : T
module SHA224  : T
module SHA256  : T
module SHA384  : T
module SHA512  : T
module SHAd256 : sig include Module_types.Basic_hash end

(* A set of simpler short-hands for common operations over varying hashes. *)

type hash = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ] with sexp

val digest      : [< hash ] -> Cstruct.t -> Cstruct.t
val mac         : [< hash ] -> key:Cstruct.t -> Cstruct.t -> Cstruct.t
val digest_size : [< hash ] -> int
val module_of   : [< hash ] -> (module T)
