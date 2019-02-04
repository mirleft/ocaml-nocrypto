val invalid_arg : ('a, Format.formatter, unit, unit, unit, 'b) format6 -> 'a
val failwith : ('a, Format.formatter, unit, unit, unit, 'b) format6 -> 'a

val ( // ) : int -> int -> int [@@inline]
(** [x // y] is the ceiling division [ceil (x / y)].

     [x // y] is [0] for any non-positive [x].

     @raise Division_by_zero when [y < 1]. *)

val imin : int -> int -> int [@@inline]
val imax : int -> int -> int [@@inline]

val until : ('a -> bool) -> (unit -> 'a) -> 'a

module Option : sig
  val get_or : ('a -> 'b) -> 'a -> 'b option -> 'b
  val ( >>= ) : 'a option -> ('a -> 'b option) -> 'b option
  val ( >>| ) : 'a option -> ('a -> 'b) -> 'b option
  val v_map : def:'a -> f:('b -> 'a) -> 'b option -> 'a
  val get : def:'a -> 'a option -> 'a
  val map : f:('a -> 'b) -> 'a option -> 'b option
  val cond : f:('a -> 'b) -> 'a option -> unit
end

val iter1 : 'a -> ('a -> 'b) -> 'b
val iter2 : 'a -> 'a -> ('a -> 'b) -> 'b
val iter3 : 'a -> 'a -> 'a -> ('a -> 'b) -> 'b

type off  = int
type size = int

module Cs : sig
  open Cstruct
  val ( <+> ) : t -> t -> t
  val ct_eq : t -> t -> bool
  val ct_find_uint8 :
    ?off:int -> f:(uint8 -> bool) -> t -> int option
  val clone : ?off:int -> ?len:int -> t -> t
  val xor : t -> t -> int -> unit
  val create : ?init:int -> int -> t
  val is_prefix : t -> t -> bool
  val set_msb : int -> t -> unit
  val split2 : t -> int -> t * t
  val split3 : t -> int -> int -> t * t * t
  val rpad : t -> int -> int -> t
  val lpad : t -> int -> int -> t
  val of_bytes : uint8 list -> t
  val of_int32s : uint32 list -> t
  val of_int64s : uint64 list -> t
  val b : uint8 -> t
  val shift_left_inplace : t -> int -> unit
  val shift_right_inplace : t -> int -> unit
  val of_hex : string -> t
  val ( lsl ) : t -> int -> t
  val ( lsr ) : t -> int -> t
  val ( lxor ) : t -> t -> t
end

val xd :
  ?address:bool ->
  ?ascii:bool -> ?w:int -> unit -> Format.formatter -> Cstruct.t -> unit

val xdb :
  ?address:bool ->
  ?ascii:bool -> ?w:int -> unit -> Format.formatter -> bytes -> unit

module Boot : sig exception Unseeded_generator end

