
module Make (F : sig
  type 'a fn
  val foreign : string -> ('a -> 'b) Ctypes.fn -> ('a -> 'b) fn
end)
  =
struct

  open Ctypes

  module Libc = struct
    let memset =
      F.foreign "memset" @@ ptr char @-> int @-> size_t @-> returning (ptr void)
  end

end
