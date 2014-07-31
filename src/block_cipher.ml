
open Nc_common
open Algo_types.Block

let ba_of_cs = Cstruct.to_bigarray


module Modes = struct

  module Base_of ( C : Cipher_raw ) : Cipher_base = struct

    type key = C.ekey * C.dkey

    let of_secret cs = C.(e_of_secret cs, d_of_secret cs)

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let encrypt ~key: (key, _) plain =
      let cipher = Cstruct.create block_size in
      ( C.encrypt_block ~key plain cipher ; cipher )

    let decrypt ~key: (_, key) cipher =
      let plain = Cstruct.create block_size in
      ( C.decrypt_block ~key cipher plain ; plain )
  end

  module ECB_of ( C : Cipher_raw ) : ECB = struct

    open Cstruct

    type key = C.ekey * C.dkey

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let of_secret sec = C.(e_of_secret sec, d_of_secret sec)

    let encrypt, decrypt =
      let ecb f key source =
        let rec loop src = function
          | dst when Cs.null dst -> ()
          | dst ->
              f ~key src dst ;
              loop (shift src block_size)
                   (shift dst block_size) in
        let dst = create @@ len source in
        ( loop source dst ; dst ) in
      (fun ~key:(key, _) -> ecb C.encrypt_block key),
      (fun ~key:(_, key) -> ecb C.decrypt_block key)

  end

  module CBC_of ( C : Cipher_raw ) : CBC = struct

    open Cstruct

    type result = { message : Cstruct.t ; iv : Cstruct.t }
    type key    = C.ekey * C.dkey

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let of_secret sec = C.(e_of_secret sec, d_of_secret sec)

    let encrypt ~key:(key, _) ~iv plain =
      let rec loop iv = function
        | plain when Cs.null plain -> iv
        | plain ->
            Cs.xor_into iv plain block_size ;
            C.encrypt_block ~key plain plain ;
            loop (sub plain 0 block_size)
                 (shift plain block_size)
      in
      let dst = Cs.clone plain in
      let iv' = loop iv dst in
      { message = dst ; iv = iv' }

    let decrypt ~key:(_, key) ~iv cipher =
      let rec loop iv src = function
        | dst when Cs.null dst -> iv
        | dst ->
            C.decrypt_block ~key src dst ;
            Cs.xor_into iv dst block_size ;
            loop (sub src 0 block_size)
                 (shift src block_size)
                 (shift dst block_size)
      in
      let dst = create @@ len cipher in
      let iv' = loop iv cipher dst in
      { message = dst ; iv = iv' }

  end

  module CTR_of ( C : Cipher_raw ) ( CNT : Counter ) : CTR = struct

    open Cstruct

    type key = C.ekey

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let of_secret = C.e_of_secret

    let stream ~key ~ctr size =
      let rec loop ctr cs = function
        | 0 -> ()
        | n ->
            C.encrypt_block ~key ctr cs ;
            CNT.increment ctr ;
            loop ctr (shift cs block_size) (pred n) in
      let blocks = cdiv size block_size in
      let res    = create (blocks * block_size) in
      loop ctr res blocks ;
      sub res 0 size

    let encrypt ~key ~ctr msg =
      let size = len msg in
      let res  = stream ~key ~ctr size in
      Cs.xor_into msg res size ;
      res

    let decrypt = encrypt

  end

  module GCM_of ( C : Cipher_base ) : GCM = struct

    assert (C.block_size = 16)

    type result = { message : Cstruct.t ; tag : Cstruct.t }
    type key    = C.key

    let of_secret = C.of_secret

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let encrypt ~key ~iv ?adata cs =
      let (message, tag) =
        Gcm.gcm ~cipher:C.encrypt ~mode:`Encrypt ~key ~iv ?adata cs
      in { message ; tag }

    let decrypt ~key ~iv ?adata cs =
      let (message, tag) =
        Gcm.gcm ~cipher:C.encrypt ~mode:`Decrypt ~key ~iv ?adata cs
      in { message ; tag }

  end

end

module Counters = struct

  open Cstruct
  (* XXX Counters for k*8 block sizes. *)

  module Inc_LE = struct

    let increment cs =
      let rec inc cs i n =
        if n >= 8 then
          let b = Int64.succ LE.(get_uint64 cs i) in
          LE.set_uint64 cs i b ;
          if b = 0L then inc cs (i + 8) (n - 8) in
      inc cs 0 (len cs)
  end

  module Inc_BE = struct

    let increment cs =
      let rec inc cs i =
        if i >= 0 then
          let b = Int64.succ BE.(get_uint64 cs i) in
          BE.set_uint64 cs i b ;
          if b = 0L then inc cs (i - 8) in
      inc cs (len cs - 8)
  end
end

module Bindings = Native.Bindings (Nc_generated)
module Conv     = Native.Conv

module AES = struct

(*   module Raw : Cipher_raw = struct

    open Native

    type ekey = ba
    type dkey = ba

    let e_of_secret = o aes_create_enc ba_of_cs
    and d_of_secret = o aes_create_dec ba_of_cs

    let key_sizes  = [| 16; 24; 32 |]
    let block_size = 16

    let encrypt_block ~key src dst =
      aes_encrypt_into key (ba_of_cs src) (ba_of_cs dst)

    and decrypt_block ~key src dst =
      aes_decrypt_into key (ba_of_cs src) (ba_of_cs dst)
  end *)

  module Raw : Cipher_raw = struct

    open Bindings

    let key_sizes  = [| 16; 24; 32 |]
    let block_size = 16

    type ekey = (Unsigned.ulong Ctypes.ptr) * int
    type dkey = (Unsigned.ulong Ctypes.ptr) * int

    let bail msg = invalid_arg ("Nocrypto: AES: " ^ msg)

    let of_secret ~init cs =
      let size = cs.Cstruct.len in
      if size <> 16 && size <> 24 && size <> 32 then
        bail "secret is not 16, 24 or 32 bytes" ;
      let rk = Ctypes.(allocate_n ulong ~count:(AES.rklength size)) in
      init rk Conv.(cs_ptr cs) (size * 8) ;
      (rk, AES.nrounds size)

    let e_of_secret cs = of_secret ~init:AES.setup_enc cs
    and d_of_secret cs = of_secret ~init:AES.setup_dec cs

    let transform ~f ~key:(rk, rounds) src dst =
      if src.Cstruct.len < 16 || dst.Cstruct.len < 16 then
        bail "message or ciphertext is shorter than 16 bytes" ;
      f rk rounds Conv.(cs_ptr src) Conv.(cs_ptr dst)

    let encrypt_block ~key src dst = transform ~f:AES.enc ~key src dst
    and decrypt_block ~key src dst = transform ~f:AES.dec ~key src dst
  end

  module Base = Modes.Base_of (Raw)

  module ECB = Modes.ECB_of (Raw)
  module CBC = Modes.CBC_of (Raw)
  module CTR = Modes.CTR_of (Raw)
  module GCM = Modes.GCM_of (Base)
end


module DES = struct

  module Raw = struct

    open Native

    type ekey = ba
    type dkey = ba

    let e_of_secret k = des3_create_key (ba_of_cs k) 0
    and d_of_secret k = des3_create_key (ba_of_cs k) 1

    let key_sizes  = [| 24 |]
    let block_size = 8

    let encrypt_block ~key src dst =
      des3_xform_into key (ba_of_cs src) (ba_of_cs dst)

    let decrypt_block = encrypt_block
  end

  module Base = Modes.Base_of (Raw)

  module ECB = Modes.ECB_of (Raw)
  module CBC = Modes.CBC_of (Raw)
  module CTR = Modes.CTR_of (Raw)
end

module type Counter = sig include Counter end

module type T_RAW = sig include Cipher_raw end
module type T_ECB = sig include ECB end
module type T_CBC = sig include CBC end
module type T_GCM = sig include GCM end
module type T_CTR = functor (C : Counter) -> sig include CTR end
