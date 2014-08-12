
module type T = sig

  type t

  val zero : t
  val one  : t

  val (lsr)  : t -> int -> t
  val (lsl)  : t -> int -> t
  val (land) : t -> t -> t

  val (+)  : t -> t -> t
  val (-)  : t -> t -> t

  val succ : t -> t
  val pred : t -> t

  val of_int   : int -> t
  val of_int32 : int32 -> t
  val of_int64 : int64 -> t
  val to_int   : t -> int
  val to_int32 : t -> int32
  val to_int64 : t -> int64
  val to_string : t -> string

  val bit_bound : t -> int

  val bits            : t -> int
  val of_bits_be      : Cstruct.t -> int -> t
  val of_cstruct_be   : Cstruct.t -> t
  val to_cstruct_be   : ?size:int -> t -> Cstruct.t
  val into_cstruct_be : t -> Cstruct.t -> unit

end

module Int   : T with type t = int
module Int32 : T with type t = int32
module Int64 : T with type t = int64 
module Z     : T with type t = Z.t
