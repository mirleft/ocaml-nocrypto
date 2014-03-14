module type T = sig
  type t
  val zero : t
  val one  : t
  val (lsr)  : t -> int -> t
  val (lsl)  : t -> int -> t
  val (land) : t -> t -> t
  val (+)  : t -> t -> t
  val (-)  : t -> t -> t
  val pred : t -> t
  val of_int : int -> t
  val bound : t -> int
  val to_string : t -> string
end

module Int = struct
  type t = int
  let zero = 0 and one  = 1
  let (lsr)  = (lsr)
  let (lsl)  = (lsl)
  let (land) = (land)
  let (+)  = (+)
  let (-)  = (-)
  let pred = pred
  let bound _ = 64
  let of_int x = x
  let to_string = string_of_int
end

module Int32 = struct
  include Int32
  let (lsr)  = shift_right
  let (lsl)  = shift_left
  let (land) = logand
  let (+)    = add
  let (-)    = sub
  let bound _ = 32
end

module Int64 = struct
  include Int64
  let (lsr)  = shift_right
  let (lsl)  = shift_left
  let (land) = logand
  let (+)    = add
  let (-)    = sub
  let bound _ = 64
end

module Z = struct
  let bound z = Z.size z * 64
  include Z
  let (lsr) = shift_right
  let (lsl) = shift_left
end
