
open Bigarray

type bigstring = (char, int8_unsigned_elt, c_layout) Array1.t

open Ctypes
open PosixTypes

module Conv = struct

  let bigstring_create = Bigarray.(Array1.create char c_layout)

  let bs_ptr bs = bigarray_start array1 bs

  let cs_ptr cs =
    bigarray_start array1 Cstruct.(to_bigarray cs)
(*     bigarray_start array1 cs.Cstruct.buffer +@ cs.Cstruct.off *) (* XXX *)

  let cs_len_size_t cs = Unsigned.Size_t.of_int cs.Cstruct.len

end

module Bindings (F : sig
  type 'a fn
  val foreign : string -> ('a -> 'b) Ctypes.fn -> ('a -> 'b) fn
end) = struct

  module Gen_hash (H : sig val ssize : int val pre : string end) = struct

    let ssize = H.ssize

    let init =
      (* state -> unit *)
      F.foreign (H.pre ^ "_Init")   @@ ptr char @-> returning void
    and update =
      (* state -> input -> unit *)
      F.foreign (H.pre ^ "_Update") @@ ptr char @-> ptr char @-> size_t @-> returning void
    and final =
      (* result -> state -> unit *)
      F.foreign (H.pre ^ "_Final")  @@ ptr char @-> ptr char @-> returning void
  end

  open Nc_native_sizes

  module MD5    = Gen_hash (struct let ssize = sizeof_MD5_CTX let pre = "MD5"    end)
  module SHA1   = Gen_hash (struct let ssize = sizeof_SHA_CTX let pre = "SHA1"   end)
  module SHA224 = Gen_hash (struct let ssize = sizeof_SHA_CTX let pre = "SHA224" end)
  module SHA256 = Gen_hash (struct let ssize = sizeof_SHA_CTX let pre = "SHA256" end)
  module SHA384 = Gen_hash (struct let ssize = sizeof_SHA_CTX let pre = "SHA384" end)
  module SHA512 = Gen_hash (struct let ssize = sizeof_SHA_CTX let pre = "SHA512" end)

  module AES = struct

    let setup_enc = F.foreign "rijndaelSetupEncrypt" @@
      ptr ulong @-> ptr char @-> int @-> returning int

    and setup_dec = F.foreign "rijndaelSetupDecrypt" @@
      ptr ulong @-> ptr char @-> int @-> returning int

    and enc = F.foreign "rijndaelEncrypt" @@
      ptr ulong @-> int @-> ptr char @-> ptr char @-> returning void

    and dec = F.foreign "rijndaelDecrypt" @@
      ptr ulong @-> int @-> ptr char @-> ptr char @-> returning void

    let rklength keybytes = keybytes + 28
    and nrounds  keybytes = keybytes / 4 + 6
  end

  module D3DES = struct

    let en0 = 0
    and de1 = 1

    let des3key = F.foreign "des3key" @@ ptr char @-> short @-> returning void
    and cp3key  = F.foreign "cp3key"  @@ ptr ulong @-> returning void
    and use3key = F.foreign "use3key" @@ ptr ulong @-> returning void
    and ddes    = F.foreign "Ddes"    @@ ptr char @-> ptr char @-> returning void
  end

end
