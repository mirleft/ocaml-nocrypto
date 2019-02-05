open Nocrypto_uncommon

module type S = sig
  type t
  val zero : t
  val one : t
  val bit_size : t -> int
  val of_cstruct_be : bits:int -> Cstruct.t -> t
  val pp : Format.formatter -> t -> unit
  val (+) : t -> t -> t
  val (-) : t -> t -> t
end

(** XXX defensive; fix in Cs *)
let lpad cs n = if Cstruct.len cs < n then Cs.lpad cs n 0 else cs

module Int32: S with type t = int32 = struct

  type t = int32

  open Int32

  let (lsr) = shift_right_logical and (land) = logand

  let of_cstruct_be ~bits cs =
    let bits = imin 32 bits |> imax 0 in
    let x = Cstruct.BE.get_uint32 (lpad cs 4) 0 in
    shift_right_logical x (32 - bits) [@@inline]

  let t = "\x00\x01\x02\x02\x03\x03\x03\x03\x04\x04\x04\x04\x04\x04\x04\x04"

  let bit_size x =
    let (i, x) = if x land 0xffff0000l <> 0l then (16, x lsr 16) else (0, x) in
    let (i, x) = if x land 0xff00l <> 0l then (i + 8, x lsr 8) else (i, x) in
    let (i, x) = if x land 0xf0l <> 0l then (i + 4, x lsr 4) else (i, x) in
    Char.code t.[to_int (x land 0xfl)] + i

  let zero = 0l and one = 1l
  let (+) = add and (-) = sub
  let pp ppf = Format.fprintf ppf "%ld"
end

module Int64: S with type t = int64 = struct

  type t = int64

  open Int64

  let (lsr) = shift_right_logical and (land) = logand

  let of_cstruct_be ~bits cs =
    let bits = imin 64 bits |> imax 0 in
    let x = Cstruct.BE.get_uint64 (lpad cs 8) 0 in
    shift_right_logical x (64 - bits) [@@inline]

  let bit_size x =
    if x land 0xffffffff00000000L <> 0L then
      32 + Int32.bit_size (to_int32 (x lsr 32))
    else Int32.bit_size (to_int32 x) [@@inline]

  let zero = 0L and one = 1L
  let (+) = add and (-) = sub
  let pp ppf = Format.fprintf ppf "%Ld"
end

module Int_stuff = struct
  type t = int
  let zero = 0 and one = 1
  let (+) = (+) and (-) = (-)
  let pp ppf = Format.fprintf ppf "%d"
end

module Int_32 = struct
  include Int_stuff
  let bit_size x = Stdlib.Int32.of_int x |> Int32.bit_size
  let of_cstruct_be ~bits cs =
    let n = (Int32.of_cstruct_be [@inlined]) ~bits cs in
    Stdlib.Int32.to_int n land max_int
end

module Int_64 = struct
  include Int_stuff
  let bit_size x = Stdlib.Int64.of_int x |> Int64.bit_size
  let of_cstruct_be ~bits cs =
    let n = (Int64.of_cstruct_be [@inlined]) ~bits cs in
    Stdlib.Int64.to_int n land max_int
end

module Int =
  (val if Sys.word_size = 64 then
          (module Int_64: S with type t = int)
       else (module Int_32: S with type t = int))
