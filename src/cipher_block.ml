open Uncommon

module T = struct

  module type Counter = sig val increment : Cstruct.t -> unit end

  module type Raw = sig

    type ekey
    type dkey

    val e_of_secret : Cstruct.t -> ekey
    val d_of_secret : Cstruct.t -> dkey

    val key_sizes  : int array
    val block_size : int
    val encrypt_block : key:ekey -> Cstruct.t -> Cstruct.t -> unit
    val decrypt_block : key:dkey -> Cstruct.t -> Cstruct.t -> unit
  end

  module type Base = sig
    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
  end

  module type ECB = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
  end

  module type CBC = sig

    type key
    type result = { message : Cstruct.t ; iv : Cstruct.t }
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
    val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> result
  end

  module type CTR = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val stream  : key:key -> ctr:Cstruct.t -> int -> Cstruct.t
    val encrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> Cstruct.t
  end

  module type GCM = sig
    type key
    type result = { message : Cstruct.t ; tag : Cstruct.t }
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
    val decrypt : key:key -> iv:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> result
  end

  module type CCM = sig
    type key
    val of_secret : maclen:int -> Cstruct.t -> key

    val key_sizes  : int array
    val mac_sizes  : int array
    val block_size : int
    val encrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> nonce:Cstruct.t -> ?adata:Cstruct.t -> Cstruct.t -> Cstruct.t option
  end
end

module Modes = struct

  module Base_of (C : T.Raw) : T.Base = struct

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

  module ECB_of (C : T.Raw) : T.ECB = struct

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

  module CBC_of (C : T.Raw) : T.CBC = struct

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

  module CTR_of (C : T.Raw) (CNT : T.Counter) : T.CTR = struct

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
      let len_ctr = len ctr in
      let tmp_ctr = create len_ctr in
      let res    = create (blocks * block_size) in
      blit ctr 0 tmp_ctr 0 len_ctr;
      loop tmp_ctr res blocks ;
      sub res 0 size


    let encrypt ~key ~ctr msg =
      let size = len msg in
      let res  = stream ~key ~ctr size in
      Cs.xor_into msg res size ;
      res

    let decrypt = encrypt

  end

  module GCM_of (C : T.Base) : T.GCM = struct

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

  module CCM_of (C : T.Raw) : T.CCM = struct

    assert (C.block_size = 16)

    type key = C.ekey * int

    let bail msg = invalid_arg ("Nocrypto: CCM: " ^ msg)

    let mac_sizes = [| 4; 6; 8; 10; 12; 14; 16 |]

    let of_secret ~maclen sec =
      if Arr.mem maclen mac_sizes then
        (C.e_of_secret sec, maclen)
      else bail "invalid MAC length"

    let (key_sizes, block_size) = C.(key_sizes, block_size)

    let encrypt ~key:(key, maclen) ~nonce ?adata cs =
      Ccm.generation_encryption ~cipher:C.encrypt_block ~key ~nonce ~maclen ?adata cs

    let decrypt ~key:(key, maclen) ~nonce ?adata cs =
      Ccm.decryption_verification ~cipher:C.encrypt_block ~key ~nonce ~maclen ?adata cs

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

open Native

module AES = struct

  module Raw : T.Raw = struct

    open Bindings

    let key_sizes  = [| 16; 24; 32 |]
    let block_size = 16

    type ekey = (Unsigned.ulong Ctypes.ptr) * int
    type dkey = (Unsigned.ulong Ctypes.ptr) * int

    let bail msg = invalid_arg ("Nocrypto: AES: " ^ msg)

    let of_secret ~init sec =
      let size = sec.Cstruct.len in
      if size <> 16 && size <> 24 && size <> 32 then
        bail "secret is not 16, 24 or 32 bytes" ;
      let rk = Ctypes.(allocate_n ulong ~count:(AES.rklength size)) in
      init rk Conv.(cs_ptr sec) (size * 8) ;
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
  module CCM = Modes.CCM_of (Raw)
end


module DES = struct

  module Raw = struct

    open Bindings

    let key_sizes  = [| 24 |]
    let block_size = 8

    type ekey = Unsigned.ulong Ctypes.ptr
    type dkey = Unsigned.ulong Ctypes.ptr

    let bail msg = invalid_arg ("Nocrypto: DES: " ^ msg)

    let of_secret ~direction sec =
      if sec.Cstruct.len <> 24 then bail "secret is not 24 bytes" ;
      let cooked = Ctypes.(allocate_n ulong ~count:96) in
      D3DES.des3key Conv.(cs_ptr sec) direction ;
      D3DES.cp3key cooked ;
      cooked

    let e_of_secret cs = of_secret ~direction:D3DES.en0 cs
    and d_of_secret cs = of_secret ~direction:D3DES.de1 cs

    let encrypt_block ~(key:ekey) src dst =
      if src.Cstruct.len < 8 || dst.Cstruct.len < 8 then
        bail "message or ciphertext is shorter than 8 bytes" ;
      D3DES.use3key key;
      D3DES.ddes Conv.(cs_ptr src) Conv.(cs_ptr dst)

    let decrypt_block = encrypt_block

  end

  module Base = Modes.Base_of (Raw)

  module ECB = Modes.ECB_of (Raw)
  module CBC = Modes.CBC_of (Raw)
  module CTR = Modes.CTR_of (Raw)

end
