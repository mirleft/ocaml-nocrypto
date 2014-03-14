open Common

module type T = sig
  type t
  val bound : t -> int
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
  val of_int64 : int64 -> t
  val of_int32 : int32 -> t
  val to_string : t -> string
end

module Int = struct
  type t = int
  let bound _ = 64
  let zero = 0 and one  = 1
  let (lsr)  = (lsr)
  let (lsl)  = (lsl)
  let (land) = (land)
  let (+)  = (+)
  let (-)  = (-)
  let succ = succ
  let pred = pred
  let of_int     = id
  let of_int64 _ = assert false
  let of_int32   = Int32.to_int
  let to_string  = string_of_int
end

module Int32 = struct
  include Int32
  let bound _ = 32
  let (lsr)  = shift_right
  let (lsl)  = shift_left
  let (land) = logand
  let (+)    = add
  let (-)    = sub
  let of_int64 _ = assert false
  let of_int32   = id
end

module Int64 = struct
  include Int64
  let bound _ = 64
  let (lsr)  = shift_right
  let (lsl)  = shift_left
  let (land) = logand
  let (+)    = add
  let (-)    = sub
  let of_int64 = id
end

module Z = struct
  let bound z = Z.size z * 64
  include Z
  let (lsr) = shift_right
  let (lsl) = shift_left
end
