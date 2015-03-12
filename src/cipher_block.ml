open Uncommon

module T = struct

  module type Counter = sig val increment : Cstruct.t -> unit end

  (* XXX old block-level sig, remove *)
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

  (* XXX old block-level + duplex sig, remove *)
  module type Base = sig
    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val encrypt : key:key -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> Cstruct.t -> Cstruct.t
  end

  module type Core = sig

    type ekey
    type dkey

    val of_secret   : Cstruct.t -> ekey * dkey
    val e_of_secret : Cstruct.t -> ekey
    val d_of_secret : Cstruct.t -> dkey

    val key   : int array
    val block : int

    (* XXX currently unsafe point *)
    val encrypt  : key:ekey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
    val decrypt  : key:dkey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
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

module Modes2 = struct

  module Raw_of (Core : T.Core) : T.Raw = struct

    type ekey = Core.ekey
    type dkey = Core.dkey

    let e_of_secret = Core.e_of_secret
    let d_of_secret = Core.d_of_secret

    let key_sizes  = Core.key
    let block_size = Core.block

    open Cstruct

    let encrypt_block ~key:key src dst =
      if src.len < block_size || dst.len < block_size then invalid_arg "xxx" ;
      Core.encrypt ~key ~blocks:1 src.buffer src.off dst.buffer dst.off

    let decrypt_block ~key:key src dst =
      if src.len < block_size || dst.len < block_size then invalid_arg "xxx" ;
      Core.decrypt ~key ~blocks:1 src.buffer src.off dst.buffer dst.off
  end

  module Base_of (Core : T.Core) : T.Base = struct

    type key = Core.ekey * Core.dkey

    let of_secret = Core.of_secret

    let key_sizes  = Core.key
    let block_size = Core.block

    open Cstruct

    let encrypt ~key:(key, _) src =
      if src.len < block_size then invalid_arg "xxx" ;
      let dst = create block_size in
      Core.encrypt ~key ~blocks:1 src.buffer src.off dst.buffer dst.off ;
      dst

    let decrypt ~key:(_, key) src =
      if src.len < block_size then invalid_arg "xxx" ;
      let dst = create block_size in
      Core.decrypt ~key ~blocks:1 src.buffer src.off dst.buffer dst.off ;
      dst
  end

  module ECB_of (Core : T.Core) : T.ECB = struct

    open Cstruct

    type key = Core.ekey * Core.dkey

    let (key_sizes, block_size) = Core.(key, block)

    let of_secret = Core.of_secret

    let (encrypt, decrypt) =
      let ecb xform key src =
        let n = len src in
        if n mod block_size <> 0 then
          Raise.invalid1 "ECB: argument not N * %d bytes" block_size ;
        let dst = create @@ len src in
        xform ~key ~blocks:(n / block_size) src.buffer src.off dst.buffer dst.off ;
        dst
      in
      (fun ~key:(key, _) src -> ecb Core.encrypt key src),
      (fun ~key:(_, key) src -> ecb Core.decrypt key src)

  end

  module CBC_of (Core : T.Core) : T.CBC = struct

    open Cstruct

    type result = { message : Cstruct.t ; iv : Cstruct.t }
    type key    = Core.ekey * Core.dkey

    let (key_sizes, block_size) = Core.(key, block)
    let block = block_size

    let of_secret = Core.of_secret

    let bounds_check ~iv cs =
      if len iv <> block then
        Raise.invalid1 "CBC: iv is not %d bytes" block ;
      if len cs mod block <> 0 then
        Raise.invalid1 "CBC: argument is not N * %d bytes" block

    let encrypt ~key:(key, _) ~iv plain =
      let () = bounds_check ~iv plain in
      let rec loop iv i_iv dst i_buf = function
        | 0 -> of_bigarray ~off:i_iv ~len:block iv
        | b ->
            Native.xor_into iv i_iv dst i_buf block ;
            Core.encrypt ~key ~blocks:1 dst i_buf dst i_buf ;
            loop dst i_buf dst (i_buf + block) (pred b)
      in
      let msg = Cs.clone plain in
      let iv = loop iv.buffer iv.off msg.buffer msg.off (len plain / block) in
      { message = msg ; iv }

    let decrypt ~key:(_, key) ~iv src =
      let ()  = bounds_check ~iv src
      and msg = create (len src) in
      match len src / block with
      | 0 -> { message = msg ; iv }
      | b ->
          Core.decrypt ~key ~blocks:b src.buffer src.off msg.buffer msg.off ;
          Native.xor_into iv.buffer iv.off msg.buffer msg.off block ;
          Native.xor_into src.buffer src.off msg.buffer (msg.off + block) ((b - 1) * block) ;
          { message = msg ; iv = sub src (len src - block) block }

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

open Bigarray
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

module AES2 = struct

  module Core : T.Core = struct

    let key   = [| 16; 24; 32 |]
    let block = 16

    type ekey = buffer * int
    type dkey = buffer * int

    let of_secret_with init { Cstruct.buffer ; off ; len } =
      let rounds =
        match len with
        | 16|24|32 -> len / 4 + 6
        | _        -> Raise.invalid1 "AES: invalid key size (%d)" len in
      let rk = Native.(buffer @@ AES.rk_s rounds) in
      init buffer off rk rounds ;
      (rk, rounds)

    let derive_d ?e buf off rk rs = Native.AES.derive_d buf off rk rs e

    let e_of_secret = of_secret_with Native.AES.derive_e
    let d_of_secret = of_secret_with (derive_d ?e:None)

    let of_secret secret =
      let (e, _) as ekey = e_of_secret secret in
      (ekey, of_secret_with (derive_d ~e) secret)

    (* XXX arg order ocaml<->c slows down *)
    (* XXX bounds checks *)

    let encrypt ~key:(e, rounds) ~blocks src off1 dst off2 =
      Native.AES.enc e rounds blocks src off1 dst off2

    let decrypt ~key:(d, rounds) ~blocks src off1 dst off2 =
      Native.AES.dec d rounds blocks src off1 dst off2

  end

  module ECB = Modes2.ECB_of (Core)
  module CBC = Modes2.CBC_of (Core)

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

module DES2 = struct

  module Core : T.Core = struct

    let key   = [| 24 |]
    let block = 8

    type ekey = buffer
    type dkey = buffer

    let k_s = Native.DES.k_s ()

    let gen_of_secret ~direction { Cstruct.buffer ; off ; len } =
      if len <> 24 then
        Raise.invalid1 "DES: invalid key size (%d)" len ;
      let key = Native.buffer k_s in
      Native.DES.des3key buffer off direction ;
      Native.DES.cp3key key ;
      key

    let e_of_secret = gen_of_secret ~direction:0
    let d_of_secret = gen_of_secret ~direction:1

    let of_secret secret = (e_of_secret secret, d_of_secret secret)

    let encrypt ~key ~blocks src off1 dst off2 =
      Native.DES.use3key key ;
      Native.DES.ddes blocks src off1 dst off2

    let decrypt = encrypt
  end
end
