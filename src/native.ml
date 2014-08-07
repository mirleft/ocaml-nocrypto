
type bigstring = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

module Conv = struct

  open Ctypes

  let bigstring_create =
    Bigarray.(Array1.create char c_layout)

  let bs_ptr bs = bigarray_start array1 bs

  let cs_ptr cs =
    bigarray_start array1 cs.Cstruct.buffer +@ cs.Cstruct.off
(*     bigarray_start array1 Cstruct.(to_bigarray cs) *)

  let cs_len_size_t cs =
    Unsigned.Size_t.of_int cs.Cstruct.len

  let allocate_voidp ~count =
    Ctypes.(to_voidp @@ allocate_n uint8_t ~count)

end

module Bindings = Bindings.Make (Nocrypto_generated)
