open Uncommon

module T = struct

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
    val encrypt : key:ekey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
    val decrypt : key:dkey -> blocks:int -> Native.buffer -> int -> Native.buffer -> int -> unit
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
    type result = { message : Cstruct.t ; ctr : Cstruct.t }
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int
    val stream  : key:key -> ctr:Cstruct.t -> int -> result
    val encrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> result
    val decrypt : key:key -> ctr:Cstruct.t -> Cstruct.t -> result
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

  open Cstruct

  module Raw_of (Core : T.Core) : T.Raw = struct

    type ekey = Core.ekey
    type dkey = Core.dkey

    let e_of_secret = Core.e_of_secret
    let d_of_secret = Core.d_of_secret

    let key_sizes  = Core.key
    let block_size = Core.block

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

  module CTR_of (Core : T.Core) : T.CTR = struct

    (* FIXME: CTR can easily be ~40% faster. *)

    let count_be =
      match Core.block with
      | 16 -> Native.count16be
      | 8  -> Native.count8be
      | n  -> Raise.invalid1 "CTR_of: bad block size (%d): not {8,16}" n

    type key = Core.ekey

    type result = { message : Cstruct.t ; ctr : Cstruct.t }

    let (key_sizes, block_size) = Core.(key, block)
    let of_secret = Core.e_of_secret

    let block = Core.block

    let stream ~key ~ctr n =
      let blocks = cdiv n block in
      let size   = blocks * block in
      let res    = create (size + block) in
      count_be ctr.buffer ctr.off res.buffer res.off (blocks + 1) ;
      Core.encrypt ~key ~blocks res.buffer res.off res.buffer res.off ;
      { message = sub res 0 n ; ctr = sub res size block }

    let encrypt ~key ~ctr src =
      let { message ; _ } as res = stream ~key ~ctr src.len in
      Native.xor_into src.buffer src.off message.buffer message.off src.len ;
      res

    let decrypt = encrypt

  end

end

module Counter = struct

  open Cstruct

  let incr cs =
    let rec go = function
      | n when n >= 8 ->
          let i = n - 8 in
          let x = Int64.succ @@ BE.get_uint64 cs i in
          BE.set_uint64 cs i x ;
          if x = 0L then go i
      | n when n >= 4 ->
          let i = n - 4 in
          let x = Int32.succ @@ BE.get_uint32 cs i in
          BE.set_uint32 cs i x ;
          if x = 0l then go i
      | n when n >= 2 ->
          let i = n - 2 in
          let x = succ @@ BE.get_uint16 cs i in
          BE.set_uint16 cs i x ;
          if x = 0x10000 then go i
      | 1 -> set_uint8 cs 0 @@ succ @@ get_uint8 cs 0
      | _ -> () in
    go (len cs)

end

open Bigarray

module AES = struct

  let mode =
    match Native.AES.mode () with
    | 0 -> `Generic | 1 -> `AES_NI | _ -> assert false

  module Core : T.Core = struct

    let key   = [| 16; 24; 32 |]
    let block = 16

    type ekey = Native.buffer * int
    type dkey = Native.buffer * int

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
      Native.AES.enc src off1 dst off2 e rounds blocks

    let decrypt ~key:(d, rounds) ~blocks src off1 dst off2 =
      Native.AES.dec src off1 dst off2 d rounds blocks

  end

  module ECB = Modes2.ECB_of (Core)
  module CBC = Modes2.CBC_of (Core)
  module CTR = Modes2.CTR_of (Core)

  module GCM = Modes.GCM_of (Modes2.Base_of(Core))
  module CCM = Modes.CCM_of (Modes2.Raw_of(Core))

end

module DES = struct

  module Core : T.Core = struct

    let key   = [| 24 |]
    let block = 8

    type ekey = Native.buffer
    type dkey = Native.buffer

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
      Native.DES.ddes src off1 dst off2 blocks

    let decrypt = encrypt
  end

  module ECB = Modes2.ECB_of (Core)
  module CBC = Modes2.CBC_of (Core)
  module CTR = Modes2.CTR_of (Core)

end
