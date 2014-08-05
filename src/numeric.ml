open Nc_common

module type T_core = sig
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
  val bound : t -> int
end

module type T = sig
  include T_core
  val bits            : t -> int
  val of_bits_be      : Cstruct.t -> int -> t
  val of_cstruct_be   : Cstruct.t -> t
  val to_cstruct_be   : ?size:int -> t -> Cstruct.t
  val into_cstruct_be : t -> Cstruct.t -> unit
end

module Int_core = struct
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
  let of_int    = id
  let of_int32  = Int32.to_int
  let of_int64  = Int64.to_int
  let to_int    = id
  let to_int32  = Int32.of_int
  let to_int64  = Int64.of_int
  let to_string = string_of_int
end

module Int32_core = struct
  include Int32
  let bound _ = 32
  let (lsr)  = shift_right_logical
  let (lsl)  = shift_left
  let (land) = logand
  let (+)    = add
  let (-)    = sub
  let of_int32 = id
  let of_int64 = Int64.to_int32
  let to_int32 = id
  let to_int64 = Int64.of_int32
end

module Int64_core = struct
  include Int64
  let bound _ = 64
  let (lsr)  = shift_right_logical
  let (lsl)  = shift_left
  let (land) = logand
  let (+)    = add
  let (-)    = sub
  let of_int64 = id
  let to_int64 = id
end

module Z_core = struct
  let bound z = Z.size z * 64
  include Z
  let (lsr) = shift_right
  let (lsl) = shift_left
end


module Repr ( N : T_core ) = struct

  (* If there was only, like, an instruction doing `ceil (log2 n)`... *)
  let bits i =
    if i < N.zero then invalid_arg "bits: negative number" ;

    let rec scan acc bound = function
      | i when i = N.zero -> acc
      | i when i = N.one  -> acc + 1
      | i ->
          let mid   = bound / 2 in
          let upper = N.(i lsr mid) in
          if upper = N.zero then
            scan acc (bound - mid) i
          else scan (acc + mid) (bound - mid) upper in
    scan 0 N.(bound i) i

  let of_bits_be cs b =
    let open Cstruct in
    let open BE in

    let rec loop acc i = function

      | b when b >= 64 ->
          let x = get_uint64 cs i in
          let x = N.of_int64 Int64.(shift_right_logical x 8) in
          loop N.(x + acc lsl 56) (i + 7) (b - 56)
      | b when b >= 32 ->
          let x = get_uint32 cs i in
          let x = N.of_int32 Int32.(shift_right_logical x 8) in
          loop N.(x + acc lsl 24) (i + 3) (b - 24)
      | b when b >= 16 ->
          let x = N.of_int (get_uint16 cs i) in
          loop N.(x + acc lsl 16) (i + 2) (b - 16)
      | b when b >= 8  ->
          let x = N.of_int (get_uint8 cs i) in
          loop N.(x + acc lsl 8 ) (i + 1) (b - 8 )
      | b when b > 0   ->
          let x = get_uint8 cs i and b' = 8 - b in
          N.(of_int x lsr b' + acc lsl b)
      | _              -> acc
    in
    loop N.zero 0 b

  let of_cstruct_be cs = of_bits_be cs (Cstruct.len cs * 8)

  let byte1 = N.of_int 0xff
  and byte2 = N.of_int 0xffff
  and byte3 = N.of_int 0xffffff
  and byte7 = N.of_int 0xffffffffffffff

  let into_cstruct_be n cs =
    let open Cstruct in
    let open BE in

    let rec write n = function
      | i when i >= 7 ->
          set_uint64 cs (i - 7) N.(to_int64 (n land byte7)) ;
          write N.(n lsr 56) (i - 7)
      | i when i >= 3 ->
          set_uint32 cs (i - 3) N.(to_int32 (n land byte3)) ;
          write N.(n lsr 24) (i - 3)
      | i when i >= 1 ->
          set_uint16 cs (i - 1) N.(to_int (n land byte2)) ;
          write N.(n lsr 16) (i - 2)
      | 0 -> set_uint8 cs 0 N.(to_int (n land byte1)) ;
      | _ -> ()
    in
    write n (len cs - 1)

  let to_cstruct_be ?size n =
    let cs = Cstruct.create @@ match size with
              | Some s -> s
              | None   -> cdiv (bits n) 8 in
    ( into_cstruct_be n cs ; cs )

end

module T (N : T_core) : T with type t = N.t = struct
  include N
  include Repr (N)
end

module Int   = T (Int_core  )
module Int32 = T (Int32_core)
module Int64 = T (Int64_core)
module Z     = T (Z_core    )
