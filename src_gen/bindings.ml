
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

  module Gen_hash (H : sig
    val ssize : (unit -> Unsigned.size_t) F.fn
    val name  : string
  end) = struct

    let ssize = H.ssize
    let named suff = "nc_" ^ H.name ^ "_" ^ suff

    let init =
      F.foreign (named "init") @@ ptr void @-> returning void
    and update =
      F.foreign (named "update") @@ ptr void @-> ptr char @-> uint32_t @-> returning void
    and final =
      F.foreign (named "finalize") @@ ptr void @-> ptr char @-> returning void
  end

  module Size_of = struct

    let ctx_size name =
      F.foreign ("nocrypto_stub_sizeof_" ^ name ^ "_ctx") (void @-> returning size_t)

    let md5    = ctx_size "md5"
    and sha1   = ctx_size "sha1"
    and sha256 = ctx_size "sha256"
    and sha512 = ctx_size "sha512"
  end

  module MD5    = Gen_hash (struct let ssize = Size_of.md5    let name = "md5"    end)
  module SHA1   = Gen_hash (struct let ssize = Size_of.sha1   let name = "sha1"   end)
  module SHA224 = Gen_hash (struct let ssize = Size_of.sha256 let name = "sha224" end)
  module SHA256 = Gen_hash (struct let ssize = Size_of.sha256 let name = "sha256" end)
  module SHA384 = Gen_hash (struct let ssize = Size_of.sha512 let name = "sha384" end)
  module SHA512 = Gen_hash (struct let ssize = Size_of.sha512 let name = "sha512" end)

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
