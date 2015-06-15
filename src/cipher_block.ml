open Uncommon

module S = struct

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
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int

    val next_iv : Cstruct.t -> Cstruct.t
    val encrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> iv:Cstruct.t -> Cstruct.t -> Cstruct.t
  end

  module type CTR = sig

    type key
    val of_secret : Cstruct.t -> key

    val key_sizes  : int array
    val block_size : int

    val stream  : key:key -> ctr:Cstruct.t -> ?off:int -> int -> Cstruct.t
    val encrypt : key:key -> ctr:Cstruct.t -> ?off:int -> Cstruct.t -> Cstruct.t
    val decrypt : key:key -> ctr:Cstruct.t -> ?off:int -> Cstruct.t -> Cstruct.t
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

module Counter = struct

  open Cstruct

  let incr1 cs i =
    let x = succ (get_uint8 cs i) in (set_uint8 cs i x ; x = 0x100)

  let incr2 cs i =
    let x = succ (BE.get_uint16 cs i) in (BE.set_uint16 cs i x ; x = 0x10000)

  let incr4 cs i =
    let x = Int32.succ (BE.get_uint32 cs i) in (BE.set_uint32 cs i x ; x = 0l)

  let incr8 cs i =
    let x = Int64.succ (BE.get_uint64 cs i) in (BE.set_uint64 cs i x ; x = 0L)

  let incr16 cs i = incr8 cs (i + 8) && incr8 cs i

  let add4 cs i x =
    BE.(set_uint32 cs i (Int32.add x (get_uint32 cs i)))

  let add8 cs i x =
    BE.(set_uint64 cs i (Int64.add x (get_uint64 cs i)))

  (* FIXME: overflow: higher order bits. *)
  let add16 cs i x = add8 cs (i + 8) x

end

module Modes = struct

  module CCM_of (C : S.Raw) : S.CCM = struct

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

  module Raw_of (Core : S.Core) : S.Raw = struct

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

  module ECB_of (Core : S.Core) : S.ECB = struct

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

  module CBC_of (Core : S.Core) : S.CBC = struct

    type key = Core.ekey * Core.dkey

    let (key_sizes, block_size) = Core.(key, block)
    let block = block_size

    let of_secret = Core.of_secret

    let next_iv cs = sub cs (len cs - block_size) block_size

    let bounds_check ~iv cs =
      if len iv <> block then
        Raise.invalid1 "CBC: iv is not %d bytes" block ;
      if len cs mod block <> 0 then
        Raise.invalid1 "CBC: argument is not N * %d bytes" block

    let encrypt ~key:(key, _) ~iv src =
      bounds_check ~iv src ;
      let msg = Cs.clone src in
      let dst = msg.buffer in
      let rec loop iv iv_i dst_i b =
        if b > 0 then begin
          Native.xor_into iv iv_i dst dst_i block ;
          Core.encrypt ~key ~blocks:1 dst dst_i dst dst_i ;
          loop dst dst_i (dst_i + block) (b - 1)
        end in
      loop iv.buffer iv.off msg.off (len msg / block) ;
      msg

    let decrypt ~key:(_, key) ~iv src =
      bounds_check ~iv src ;
      let msg = create (len src)
      and b   = len src / block in
      if b > 0 then begin
        Core.decrypt ~key ~blocks:b src.buffer src.off msg.buffer msg.off ;
        Native.xor_into iv.buffer iv.off msg.buffer msg.off block ;
        Native.xor_into src.buffer src.off msg.buffer (msg.off + block) ((b - 1) * block) ;
      end ;
      msg

  end

  module CTR_of (Core : S.Core) : S.CTR with type key = Core.ekey = struct

    (* FIXME: CTR has more room for speedups. *)

    let block = Core.block

    module Ctr = struct
      let (count, add) =
        match block with
        | 16 -> (Native.count16be, Counter.add16)
        | 8  -> (Native.count8be, Counter.add8)
        | n  -> Raise.invalid1 "CTR_of: bad block size (%d): not {8,16}" n
    end

    type key = Core.ekey

    let (key_sizes, block_size) = Core.(key, block)
    let of_secret = Core.e_of_secret

    let stream ~key ~ctr n =
      let blocks = cdiv n block in
      let buf    = Native.buffer (blocks * block) in
      Ctr.count ctr.buffer ctr.off buf 0 blocks ;
      Core.encrypt ~key ~blocks buf 0 buf 0 ;
      of_bigarray ~len:n buf

    let cbuf  = Cstruct.create block
    let bmask = block - 1

    let stream_shifted ~key ~ctr off n =
      let shift  = off land bmask in
      let blocks = cdiv (shift + n) block in
      let buf    = Native.buffer (blocks * block) in
      Native.blit ctr.buffer ctr.off cbuf.buffer 0 block ;
      Ctr.add cbuf 0 (Int64.of_int (off / block)) ;
      Ctr.count cbuf.buffer 0 buf 0 blocks ;
      Core.encrypt ~key ~blocks buf 0 buf 0 ;
      of_bigarray ~len:n ~off:shift buf

    let stream ~key ~ctr ?off n =
      if ctr.len <> block then
        Raise.invalid1 "CTR: counter not %d bytes" ctr.len ;
      if n < 0 then
        Raise.invalid1 "CTR: negative size (%d)" n ;
      match off with
      | None               -> stream ~key ~ctr n
      | Some k when k >= 0 -> stream_shifted ~key ~ctr k n
      | Some k             -> Raise.invalid1 "CTR: negative offset (%d)" k

    let encrypt ~key ~ctr ?off src =
      let res = stream ~key ~ctr ?off src.len in
      Native.xor_into src.buffer src.off res.buffer res.off src.len ;
      res

    let decrypt = encrypt
  end

  module GCM_of (C : S.Core) : S.GCM = struct

    module CTR = CTR_of (C)

    assert (C.block = 16)

    type result = { message : Cstruct.t ; tag : Cstruct.t }

    let z = Cs.zeros 16

    type key = {
      key  : C.ekey ;
      hkey : Gcm.GF128.hkey
    }

    let of_secret cs =
      let key = C.e_of_secret cs
      and h   = Cstruct.create 16 in
      C.encrypt ~key ~blocks:1 z.buffer z.off h.buffer h.off ;
      let hkey = Gcm.hkey h in
      { key ; hkey }

    let (key_sizes, block_size) = C.(key, block)

    let encrypt ~key:{ key ; hkey } ~iv ?adata cs =
      let encrypt ~ctr cs = CTR.encrypt ~key ~ctr cs in
      let (message, tag) =
        Gcm.gcm ~encrypt ~mode:`Encrypt ~iv ~hkey ?adata cs
      in { message ; tag }

    let decrypt ~key:{ key ; hkey } ~iv ?adata cs =
      let encrypt ~ctr cs = CTR.encrypt ~key ~ctr cs in
      let (message, tag) =
        Gcm.gcm ~encrypt ~mode:`Decrypt ~iv ~hkey ?adata cs
      in { message ; tag }

  end


end

open Bigarray

module AES = struct

  let mode =
    match Native.AES.mode () with
    | 0 -> `Generic | 1 -> `AES_NI | _ -> assert false

  module Core : S.Core = struct

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
  module GCM = Modes2.GCM_of (Core)

  module CCM = Modes.CCM_of (Modes2.Raw_of(Core))

end

module DES = struct

  module Core : S.Core = struct

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
